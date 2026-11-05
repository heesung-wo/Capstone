import test from 'node:test';
import assert from 'node:assert/strict';
import { enabledSources, buildFeed } from '../scripts/build-feed.mjs';
import { validateFeed } from '../core/remote-feed.js';

test('모든 스위치가 꺼져 있으면 어떤 소스도 공개하지 않는다', () => {
  assert.deepEqual(Object.values(enabledSources({})).filter(Boolean), []);
});

test('PUBLISH_*만 true이고 REDISTRIBUTION_CONFIRMED가 아니면 공개하지 않는다', () => {
  const e = enabledSources({ PUBLISH_URLHAUS: 'true', PUBLISH_PHISHTANK: 'true' });
  assert.equal(e.URLhaus, false);
  assert.equal(e.PhishTank, false);
});

test('PhishingDB는 PUBLISH_PHISHING_DB와 REDISTRIBUTION_CONFIRMED가 모두 true일 때만 공개한다', () => {
  assert.equal(enabledSources({ PUBLISH_PHISHING_DB: 'true' }).PhishingDB, false);
  assert.equal(enabledSources({ REDISTRIBUTION_CONFIRMED: 'true' }).PhishingDB, false);
  assert.equal(enabledSources({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_PHISHING_DB: 'true' }).PhishingDB, true);
});

test('OpenPhish는 더 이상 지원하지 않는다', () => {
  assert.equal('OpenPhish' in enabledSources({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_OPENPHISH: 'true' }), false);
});

test('PhishingDB를 공개하면 MIT 라이선스 고지가 피드에 포함된다', async () => {
  const collectors = { PhishingDB: async () => [{ url: 'https://p.invalid/a', meta: { threat: 'phishing' } }] };
  const feed = await buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_PHISHING_DB: 'true' }, { collectors });
  assert.equal(feed.notices.length, 1);
  assert.equal(feed.notices[0].source, 'PhishingDB');
  assert.equal(feed.notices[0].license, 'MIT License');
  assert.match(feed.notices[0].copyright, /Phishing\.Database Contributors/);
  validateFeed(feed);
});

test('고지가 필요 없는 소스만 켜면 notices를 넣지 않는다', async () => {
  const collectors = { URLhaus: async () => [{ url: 'https://u.invalid/a', meta: { online: true } }] };
  const feed = await buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_URLHAUS: 'true' }, { collectors });
  assert.equal(feed.notices, undefined);
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
  assert.deepEqual(Object.keys(feed.signatures[0].meta).sort(), ['confidence', 'online', 'threat', 'valid', 'verified']);
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

test('URLhaus 원본 200,000건을 자르지 않고 수동 검사 DB 피드에 유지한다', async () => {
  const rows = Array.from({ length: 200_000 }, (_, i) => ({ url: `https://bad${i}.invalid/x`, meta: { online: i % 2 === 0 } }));
  const feed = await buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_URLHAUS: 'true' }, { collectors: { URLhaus: async () => rows } });
  assert.equal(feed.signatures.length, 200_000);
  assert.ok(feed.signatures.some(x => x.url === 'https://bad199999.invalid/x'));
  assert.equal(validateFeed(feed).records.length, 200_000);
});

test('구 300,000건 전체 시그니처 제한을 초과한 피드도 검증한다', () => {
  const rows = Array.from({ length: 300_001 }, (_, i) => ({
    url: `https://large${i}.invalid/`, source: 'URLhaus', meta: {}
  }));
  const parsed = validateFeed({ schema: 1, generatedAt: new Date().toISOString(), signatures: rows });
  assert.equal(parsed.records.length, 300_001);
});

test('소스별 개수 제한 없이 각 피드의 모든 데이터를 유지한다', async () => {
  const mk = tag => Array.from({ length: 15_000 }, (_, i) => ({ url: `https://${tag}${i}.invalid/` }));
  const feed = await buildFeed(
    { REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_URLHAUS: 'true', PUBLISH_PHISHTANK: 'true' },
    { collectors: { URLhaus: async () => mk('u'), PhishTank: async () => mk('p') } }
  );
  assert.equal(feed.signatures.filter(s => s.source === 'URLhaus').length, 15_000);
  assert.equal(feed.signatures.filter(s => s.source === 'PhishTank').length, 15_000);
});

test('구 MAX_PER_SOURCE 값도 수집 건수를 제한하지 않는다', async () => {
  const rows = Array.from({ length: 9500 }, (_, i) => ({ url: `https://e${i}.invalid/` }));
  const feed = await buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_URLHAUS: 'true', MAX_PER_SOURCE: '20' }, { collectors: { URLhaus: async () => rows } });
  assert.equal(feed.signatures.length, 9500);
});

test('네 소스의 원본 48,000건을 모두 보존하며 실시간 상한과 분리한다', async () => {
  const mk = tag => Array.from({ length: 12_000 }, (_, i) => ({ url: `https://${tag}${i}.invalid/` }));
  const collectors = {
    URLhaus: async () => mk('urlhaus'),
    PhishTank: async () => mk('phishtank'),
    PhishingDB: async () => mk('phishingdb'),
    ThreatFox: async () => mk('threatfox')
  };
  const env = Object.fromEntries(['URLHAUS', 'PHISHTANK', 'PHISHING_DB', 'THREATFOX'].map(k => [`PUBLISH_${k}`, 'true']));
  const feed = await buildFeed({ ...env, REDISTRIBUTION_CONFIRMED: 'true' }, { collectors });
  assert.equal(feed.signatures.length, 48_000);
  assert.equal(validateFeed(feed).records.length, 48_000);
});

const http = status => Object.assign(new Error(`HTTP ${status}`), { httpStatus: status });
const noSleep = async () => {};
const ENV = { REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_URLHAUS: 'true', PUBLISH_PHISHING_DB: 'true' };

test('일시적인 503은 재시도해서 성공하면 정상 배포한다', async () => {
  let calls = 0;
  const logs = [];
  const collectors = { PhishingDB: async () => { if (++calls < 3) throw http(503); return [{ url: 'https://p.invalid/a', meta: {} }]; } };
  const feed = await buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_PHISHING_DB: 'true' }, { collectors, sleep: noSleep, log: m => logs.push(m) });
  assert.equal(calls, 3);
  assert.equal(feed.signatures.length, 1);
  assert.ok(logs.some(m => /재시도 \(1\/2\)/.test(m)));
});

test('403/404 같은 설정 오류는 재시도하지 않는다', async () => {
  let calls = 0;
  const collectors = { PhishingDB: async () => { calls++; throw http(403); } };
  await assert.rejects(buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_PHISHING_DB: 'true' }, { collectors, sleep: noSleep }), /HTTP 403/);
  assert.equal(calls, 1);
});

test('503이 계속되면 재시도 횟수(총 3번) 후 실패한다', async () => {
  let calls = 0;
  const collectors = { PhishingDB: async () => { calls++; throw http(503); } };
  await assert.rejects(buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_PHISHING_DB: 'true' }, { collectors, sleep: noSleep }), /HTTP 503/);
  assert.equal(calls, 3);
});

test('선택 소스가 실패해도 나머지로 배포하고, 실패한 소스의 고지는 넣지 않는다', async () => {
  const collectors = {
    URLhaus: async () => [{ url: 'https://u.invalid/a', meta: { online: true } }],
    PhishingDB: async () => { throw http(503); }
  };
  const logs = [];
  const feed = await buildFeed({ ...ENV, OPTIONAL_SOURCES: 'PhishingDB' }, { collectors, sleep: noSleep, log: m => logs.push(m) });
  assert.deepEqual(feed.signatures.map(s => s.source), ['URLhaus']);
  assert.equal(feed.notices, undefined);
  assert.ok(logs.some(m => /경고: PhishingDB/.test(m)));
});

test('선택 소스가 아니면 실패 시 전체 배포를 중단한다', async () => {
  const collectors = { URLhaus: async () => [{ url: 'https://u.invalid/a' }], PhishingDB: async () => { throw http(503); } };
  await assert.rejects(buildFeed(ENV, { collectors, sleep: noSleep }), /이전 배포본/);
});

test('선택 소스만 켰는데 전부 실패하면 빈 피드로 덮어쓰지 않고 중단한다', async () => {
  const collectors = { PhishingDB: async () => { throw http(503); } };
  await assert.rejects(
    buildFeed({ REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_PHISHING_DB: 'true', OPTIONAL_SOURCES: 'PhishingDB' }, { collectors, sleep: noSleep }),
    /성공한 소스가 없어/
  );
});
