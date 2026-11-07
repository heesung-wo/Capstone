import test from 'node:test';
import assert from 'node:assert/strict';
import { validateFeed, downloadFeed } from '../core/remote-feed.js';
import { normalizeRows } from '../scripts/build-feed.mjs';
import { parsePhishTankJson, threatfox } from '../scripts/collectors.mjs';
const sample = (signatures = [{ url: 'https://phishing.test/login', source: 'Demo', meta: { threat: 'demo' } }]) =>
  ({ schema: 1, generatedAt: new Date().toISOString(), signatures });
test('시연용 정상 피드 검증', () => {
  const feed = validateFeed(sample());
  assert.equal(feed.demoOnly, true);
  assert.equal(feed.records[0].url, 'https://phishing.test/login');
});
test('중복 데이터는 제거', () => {
  const feed = validateFeed(sample([
    { source: 'Demo', url: 'http://malware.test/demo' },
    { source: 'Demo', url: 'http://malware.test/demo' }
  ]));
  assert.equal(feed.records.length, 1);
});
test('실존 도메인을 Demo 레코드로 넣는 것을 거부', () =>
  assert.throws(() => validateFeed(sample([{ url: 'https://example.com/', source: 'Demo' }])), /\.test/));
test('빈 피드 오류 → 기존 DB 보존을 위한 검증 실패', () =>
  assert.throws(() => validateFeed(sample([])), /빈 시그니처/));
test('알 수 없는 소스 이름 거부', () =>
  assert.throws(() => validateFeed(sample([{ source: 'Unknown', url: 'https://example.test' }])), /지원하지 않는/));
test('URL을 프로토콜 없는 상태로 넣을 수 없음', () =>
  assert.throws(() => validateFeed(sample([{ source: 'URLhaus', url: 'example.com' }])), /올바르지/));
test('키가 포함된 객체의 임의 속성은 공개 피드에서 제외', () => {
  const r = validateFeed(sample([{ source: 'URLhaus', url: 'https://bad.test/', meta: { online: true, authKey: 'secret' } }]));
  assert.equal(r.records[0].meta.authKey, undefined);
});
test('설정되지 않은 배포 주소 오류', async () =>
  assert.rejects(() => downloadFeed('https://YOUR_NAME.github.io/safe-ur-link/signatures.json'), /설정/));
test('정상 HTTP JSON 다운로드', async () => {
  const r = await downloadFeed('https://example.github.io/app/signatures.json', async () => ({ ok: true, text: async () => JSON.stringify(sample()) }));
  assert.equal(r.records.length, 1);
});
test('HTTP 404는 기존 DB 적용 전에 오류', async () =>
  assert.rejects(() => downloadFeed('https://example.github.io/app/signatures.json', async () => ({ ok: false, status: 404 })), /404/));
test('HTML 보안 페이지를 데이터로 사용하지 않음', async () =>
  assert.rejects(() => downloadFeed('https://example.github.io/app/signatures.json', async () => ({ ok: true, text: async () => '<html>blocked</html>' })), /HTML/));
test('정규화 및 중복 제거', () => {
  const a = normalizeRows('URLhaus', [{ url: 'HTTPS://BAD.TEST/path#frag', meta: { online: true, extraKey: 'secret' } }, { url: 'https://bad.test/path' }]);
  assert.equal(a.length, 1);
  assert.equal(a[0].meta.extraKey, undefined);
});
test('PhishTank JSON 파싱', () => {
  const r = parsePhishTankJson(JSON.stringify([{ url: 'https://phishing.test/', verified: 'yes', online: 'yes' }]));
  assert.equal(r[0].meta.verified, true);
});
test('미인증 ThreatFox 접근은 API 호출 전 거부', async () =>
  assert.rejects(() => threatfox({ authKey: '' }), /Auth-Key/));
