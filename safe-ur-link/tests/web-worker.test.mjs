import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const feedData = JSON.parse(await readFile(new URL('../public/signatures.json', import.meta.url), 'utf8'));
const messages = [];
const requested = [];
let readyResolve;
const ready = new Promise(resolve => { readyResolve = resolve; });
globalThis.self = {
  postMessage(message) {
    messages.push(message);
    if (message.type === 'ready') readyResolve(message);
  },
  onmessage: null
};
globalThis.fetch = async requestedUrl => {
  requested.push(String(requestedUrl));
  return { ok: true, json: async () => feedData };
};
await import('../public/assets/js/scan-worker.js');
await ready;

test('웹 워커는 같은 출처 signatures.json만 읽고 데모 데이터 2건을 인덱싱한다', () => {
  assert.equal(requested.length, 1);
  assert.match(requested[0], /\/signatures\.json$/);
  assert.equal(messages.find(m => m.type === 'ready').count, 2);
});

test('웹 워커에서 입력 URL 직접 검사를 수행하며 대상 URL로 통신하지 않는다', () => {
  self.onmessage({ data: { type: 'check', id: 1, url: 'https://phishing.test/login' } });
  const hit = messages.find(m => m.type === 'check-result' && m.id === 1);
  assert.equal(hit.result.verdict, 'Malicious');
  assert.equal(requested.length, 1); // 타깃 URL 접속 없음
});

test('웹 워커에서 시그니처 미등록 URL은 위협 미탐지로 표시한다', () => {
  self.onmessage({ data: { type: 'check', id: 2, url: 'https://example.com/' } });
  const hit = messages.find(m => m.type === 'check-result' && m.id === 2);
  assert.equal(hit.result.verdict, 'No Threat Detected');
  assert.equal(requested.length, 1);
});
