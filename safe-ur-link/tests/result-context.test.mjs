import test from 'node:test';
import assert from 'node:assert/strict';

let seq = 0;
async function renderResult(url, mode) {
  const cells = {
    target: { textContent: '' },
    targetTitle: { textContent: '' },
    result: { textContent: '', innerHTML: '' }
  };
  const requests = [];
  globalThis.document = { getElementById(id) { return cells[id]; } };
  globalThis.location = { search: `?${new URLSearchParams({ url, mode })}` };
  globalThis.chrome = { runtime: {
    async sendMessage(req) {
      requests.push(req);
      return { error: '테스트 응답' };
    }
  } };
  await import(`../pages/result/result.js?testcase=${seq++}`);
  await new Promise(resolve => setImmediate(resolve));
  return { cells, requests };
}

test('선택된 일반 문구를 다른 URL로 바꾸거나 검사하지 않는다', async () => {
  const { cells, requests } = await renderResult('로그인', 'selection');
  assert.equal(cells.target.textContent, '로그인');
  assert.match(cells.targetTitle.textContent, /드래그/);
  assert.match(cells.result.textContent, /URL 형식이 아닙니다/);
  assert.equal(requests.length, 0);
});

test('선택한 URL 문자열을 원본대로 검사에 보낸다', async () => {
  const url = 'https://selected.example/경로?x=1&y=2';
  const { cells, requests } = await renderResult(url, 'selection');
  assert.equal(cells.target.textContent, url);
  assert.deepEqual(requests, [{ type: 'check', url }]);
});

