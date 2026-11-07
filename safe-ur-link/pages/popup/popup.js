import { resultHTML } from '../../shared/render.js';

const $ = id => document.getElementById(id);
const input = $('u');
const goButton = $('go');
const tabButton = $('tab');
const output = $('out');

async function run(url) {
  goButton.disabled = tabButton.disabled = true;
  output.textContent = '검사 중…';

  try {
    const result = await chrome.runtime.sendMessage({ type: 'check', url });
    output.innerHTML = `<p class="muted break">${url.replace(/&/g, '&amp;').replace(/</g, '&lt;')}</p>` + resultHTML(result);
  } catch (error) {
    console.error('URL 검사 실패:', error);
    output.textContent = 'URL 검사 중 오류가 발생했습니다. 다시 시도해 주세요.';
  } finally {
    goButton.disabled = tabButton.disabled = false;
    // 검사 버튼을 클릭한 뒤에도 곧바로 주소를 수정할 수 있도록 편집 포커스 복구.
    input.focus();
  }
}

goButton.addEventListener('click', () => {
  const url = input.value.trim();
  if (url) void run(url);
  else input.focus();
});

// Enter만 별도 처리한다. Backspace, Delete, Space, 방향키, Ctrl+V/Z/X/C 등은
// 가로채지 않고 <input>의 브라우저 기본 편집 기능에 맡긴다.
input.addEventListener('keydown', event => {
  if (event.key === 'Enter' && !event.isComposing && !event.repeat) {
    event.preventDefault();
    goButton.click();
  }
});

tabButton.addEventListener('click', async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
      input.value = tab.url;
      await run(tab.url);
    } else input.focus();
  } catch (error) {
    console.error('현재 탭 조회 실패:', error);
    output.textContent = '현재 탭 URL을 불러오지 못했습니다.';
    input.focus();
  }
});

$('opt').addEventListener('click', () => chrome.runtime.openOptionsPage());

chrome.runtime.sendMessage({ type: 'status' }).then(status => {
  const count = Object.values(status.counts || {}).reduce((sum, value) => sum + value, 0);
  $('st').textContent = count
    ? `시그니처 ${count.toLocaleString()}건`
    : '시그니처 DB가 비어 있습니다 — 설정에서 지금 업데이트를 눌러주세요';
}).catch(() => {
  $('st').textContent = '시그니처 상태를 불러오지 못했습니다.';
});

// 입력창이 활성화된 경우 Ctrl+A / Cmd+A는 브라우저 기본 동작을 그대로 사용한다.
// 검사 버튼 등 다른 요소에 포커스가 있을 때만 URL 입력창을 선택한다.
document.addEventListener('keydown', event => {
  if (!(event.ctrlKey || event.metaKey) || event.altKey || event.shiftKey || event.key.toLowerCase() !== 'a') return;
  const target = event.target;
  if (target?.isContentEditable || ['INPUT', 'TEXTAREA'].includes(target?.tagName)) return;
  event.preventDefault();
  input.focus();
  input.select();
});

input.focus();
