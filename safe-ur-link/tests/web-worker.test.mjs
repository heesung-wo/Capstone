import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const messages = [];
const requested = [];
let simulatedShardFailure = false;
const waiting = [];
function awaitMessage(predicate) {
  const previous = messages.find(predicate);
  if (previous) return Promise.resolve(previous);
  return new Promise(resolve => waiting.push({ predicate, resolve }));
}
globalThis.self = {
  postMessage(message) {
    messages.push(message);
    for (let i = waiting.length - 1; i >= 0; i--) {
      if (waiting[i].predicate(message)) {
        waiting[i].resolve(message);
        waiting.splice(i, 1);
      }
    }
  },
  onmessage: null
};
globalThis.fetch = async requestedUrl => {
  const u = new URL(String(requestedUrl));
  requested.push(u.pathname);
  if (simulatedShardFailure && /\/web-shards\/\d+\.json$/.test(u.pathname)) {
    return { ok: false, status: 503 };
  }
  if (!u.pathname.endsWith('/web-index.json') && !/\/web-shards\/\d+\.json$/.test(u.pathname)) {
    throw new Error('예상하지 못한 데이터 요청: ' + u.pathname);
  }
  return { ok: true, json: async () => JSON.parse(await readFile(u, 'utf8')) };
};
await import('../public/assets/js/scan-worker.js');
await awaitMessage(m => m.type === 'ready');

async function scan(id, url) {
  self.onmessage({ data: { type: 'check', id, url } });
  return awaitMessage(m => m.type === 'check-result' && m.id === id);
}

test('사이트 초기 표시에는 전체 피드 대신 경량 인덱스 하나만 불러온다', () => {
  assert.equal(requested.length, 1);
  assert.match(requested[0], /\/web-index\.json$/);
  assert.equal(messages.find(m => m.type === 'ready').count, 2);
});

test('정확히 일치하는 시연 URL은 관련 샤드만 불러오며 대상 사이트에 접속하지 않는다', async () => {
  const res = await scan(10001, 'https://phishing.test/login');
  assert.equal(res.result.verdict, 'Malicious');
  assert.equal(requested.length, 2);
  assert.match(requested[1], /\/web-shards\/\d+\.json$/);
  assert.ok(requested.every(p => !p.includes('phishing.test')));
});

test('동일 샤드 재검사는 메모리 캐시를 사용한다', async () => {
  const count = requested.length;
  const res = await scan(10002, 'HTTPS://PHISHING.TEST/login#fragment');
  assert.equal(res.result.verdict, 'Malicious');
  assert.equal(requested.length, count);
});

test('미등록 URL은 시그니처를 조회했더라도 위협 미탐지 판정한다', async () => {
  const res = await scan(10003, 'https://example.com/');
  assert.equal(res.result.verdict, 'No Threat Detected');
  assert.ok(requested.every(p => !p.includes('example.com')));
});

test('잘못된 주소는 외부 요청을 하지 않고 입력 오류로 반환한다', async () => {
  const count = requested.length;
  const res = await scan(10004, 'http://[]');
  assert.match(res.result.error, /URL/);
  assert.equal(requested.length, count);
});


test('샤드 다운로드 실패는 No Threat Detected가 아니라 검사 오류로 표시한다', async () => {
  simulatedShardFailure = true;
  const response = await scan(10005, 'https://different-unseen-domain.test/neverchecked');
  simulatedShardFailure = false;
  assert.match(response.error, /503|다운로드/);
  assert.equal(response.result, undefined);
});
