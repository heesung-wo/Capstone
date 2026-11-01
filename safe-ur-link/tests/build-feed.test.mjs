import test from 'node:test';
import assert from 'node:assert/strict';
import { enabledSources, buildFeed, pickTop, MAX_PER_SOURCE } from '../scripts/build-feed.mjs';
import { validateFeed } from '../core/remote-feed.js';

test('모든 스위치가 꺼져 있으면 어떤 소스도 공개하지 않는다', () => {
  assert.deepEqual(Object.values(enabledSources({})).filter(Boolean), []);
});

test('PUBLISH_*만 true이고 REDISTRIBUTION_CONFIRMED가 아니면 공개하지 않는다', () => {
  const e = enabledSources({ PUBLISH_URLHAUS: 'true', PUBLISH_PHISHTANK: 'true' });
  assert.equal(e.URLhaus, false);
  assert.equal(e.PhishTank, false);
});

test('OpenPhish는 서면 허가 스위치가 추가로 필요하다', () => {
  const base = { REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_OPENPHISH: 'true' };
  assert.equal(enabledSources(base).OpenPhish, false);
  assert.equal(enabledSources({ ...base, OPENPHISH_WRITTEN_PERMISSION: 'true' }).OpenPhish, true);
});

test('공개 소스가 없으면 .test 시연 데이터만 만들고 확장 프로그램 검증을 통과한다', async () => {
  const feed = await buildFeed({});
  const parsed = validateFeed(feed);
  assert.equal(parsed.demoOnly, true);
  assert.ok(parsed.records.every(r => new URL(r.url).hostname.endsWith('.test')));
});

test('허용된 소스만 수집하고 비민감 메타만 남긴다', async () => {
  const called = [];
  const collectors = {
    URLhaus: async () => { called.push('URLhaus'); return [{ url: 'https://evil.invalid/a#frag', meta: { online: true, threat: 'malware_download', tags: ['x'], last_online: 'secret' } }]; },
    PhishTank: async () => { called.push('PhishTank'); return []; }
  };
  const feed = await buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_URLHAUS: 'true', PUBLISH_PHISHTANK: 'true' }, { collectors });
  assert.deepEqual(called.sort(), ['PhishTank', 'URLhaus']);
  assert.equal(feed.signatures.length, 1);
  assert.equal(feed.signatures[0].url, 'https://evil.invalid/a');   // fragment 제거
  assert.deepEqual(Object.keys(feed.signatures[0].meta).sort(), ['confidence', 'online', 'threat', 'verified']);
  validateFeed(feed);
});

test('수집 실패 시 빌드를 중단하고 에러 메시지의 비밀 키를 가린다', async () => {
  const collectors = { URLhaus: async () => { throw new Error('boom abc-secret-123 boom'); } };
  await assert.rejects(
    buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_URLHAUS: 'true', ABUSE_CH_AUTH_KEY: 'abc-secret-123' }, { collectors }),
    e => /이전 배포본/.test(e.message) && !e.message.includes('abc-secret-123') && e.message.includes('***')
  );
});

test('모든 소스가 정상이지만 결과가 비어 있으면 emptyDataset로 표시한다', async () => {
  const collectors = { ThreatFox: async () => [] };
  const feed = await buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_THREATFOX: 'true' }, { collectors });
  assert.equal(feed.emptyDataset, true);
  validateFeed(feed);
});

test('건수가 매우 많아도 호출 스택이 넘치지 않고 소스별 상한(10,000)만 남는다 (회귀 테스트)', async () => {
  const rows = Array.from({ length: 200_000 }, (_, i) => ({ url: `https://bad${i}.invalid/x`, meta: { online: i % 2 === 0 } }));
  const feed = await buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_URLHAUS: 'true' }, { collectors: { URLhaus: async () => rows } });
  assert.equal(MAX_PER_SOURCE, 10_000);
  assert.equal(feed.signatures.length, 10_000);
});

test('상한은 각 소스에 따로 적용된다', async () => {
  const mk = tag => Array.from({ length: 15_000 }, (_, i) => ({ url: `https://${tag}${i}.invalid/` }));
  const feed = await buildFeed(
    { REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_URLHAUS: 'true', PUBLISH_PHISHTANK: 'true' },
    { collectors: { URLhaus: async () => mk('u'), PhishTank: async () => mk('p') } }
  );
  assert.equal(feed.signatures.filter(s => s.source === 'URLhaus').length, 10_000);
  assert.equal(feed.signatures.filter(s => s.source === 'PhishTank').length, 10_000);
});

test('상한을 넘으면 활성 → 검증됨 → 최근 등록 순으로 남긴다', () => {
  const rows = [
    { url: 'https://old-offline.invalid/', source: 'URLhaus', meta: { online: false, first_seen: '2026-10-30T00:00:00Z' } },
    { url: 'https://online-old.invalid/', source: 'URLhaus', meta: { online: true, first_seen: '2026-01-01T00:00:00Z' } },
    { url: 'https://online-new.invalid/', source: 'URLhaus', meta: { online: true, first_seen: '2026-10-01T00:00:00Z' } },
    { url: 'https://online-verified.invalid/', source: 'URLhaus', meta: { online: true, verified: true, first_seen: '2025-01-01T00:00:00Z' } }
  ];
  assert.deepEqual(pickTop(rows, 3).map(r => r.url),
    ['https://online-verified.invalid/', 'https://online-new.invalid/', 'https://online-old.invalid/']);
});

test('상한 이하이면 순서와 내용을 그대로 유지한다', () => {
  const rows = [{ url: 'https://a.invalid/', source: 'X', meta: {} }, { url: 'https://b.invalid/', source: 'X', meta: {} }];
  assert.equal(pickTop(rows, 10), rows);
});

test('MAX_PER_SOURCE 환경변수로 상한을 바꿀 수 있다', async () => {
  const rows = Array.from({ length: 50 }, (_, i) => ({ url: `https://e${i}.invalid/` }));
  const feed = await buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_URLHAUS: 'true', MAX_PER_SOURCE: '20' }, { collectors: { URLhaus: async () => rows } });
  assert.equal(feed.signatures.length, 20);
});

test('전체 한도(30만 건)는 안전장치로 남아 있고 소스별 건수를 알려준다', async () => {
  const rows = Array.from({ length: 300_001 }, (_, i) => ({ url: `https://z${i}.invalid/` }));
  await assert.rejects(
    buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_URLHAUS: 'true', MAX_PER_SOURCE: '1000000' }, { collectors: { URLhaus: async () => rows } }),
    /URLhaus 300001건/
  );
});
