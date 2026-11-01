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
