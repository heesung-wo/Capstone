import { resultHTML } from '../../shared/render.js';
const $ = id => document.getElementById(id);
async function run(url) {
  $('go').disabled = $('tab').disabled = true; $('out').textContent = '검사 중…';
  const r = await chrome.runtime.sendMessage({ type: 'check', url });
  $('out').innerHTML = `<p class="muted break">${url.replace(/</g, '&lt;')}</p>` + resultHTML(r);
  $('go').disabled = $('tab').disabled = false;
}
$('go').onclick = () => $('u').value.trim() && run($('u').value.trim());
$('u').onkeydown = e => e.key === 'Enter' && $('go').click();
$('tab').onclick = async () => {
  const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (t?.url) { $('u').value = t.url; run(t.url); }
};
$('opt').onclick = () => chrome.runtime.openOptionsPage();
chrome.runtime.sendMessage({ type: 'status' }).then(s => {
  const n = Object.values(s.counts || {}).reduce((a, b) => a + b, 0);
  $('st').textContent = n ? `시그니처 ${n.toLocaleString()}건` : '시그니처 DB가 비어 있습니다 — 설정에서 업데이트하세요';
});

// Ctrl+V / Cmd+V 붙여넣기 지원: 기본 붙여넣기가 막히는 환경에서도 클립보드를 직접 읽어 입력창에 넣는다
const input = $('u');
input.focus();
async function pasteFromClipboard() {
  try {
    const text = (await navigator.clipboard.readText()).trim();
    if (!text) return;
    input.setRangeText(text, input.selectionStart, input.selectionEnd, 'end');
    return true;
  } catch { return false; }
}
input.addEventListener('keydown', async e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'v') {
    e.preventDefault();
    if (await pasteFromClipboard() && /^\S+$/.test(input.value.trim())) $('go').click();
  }
});
input.addEventListener('paste', e => {           // 마우스 우클릭 > 붙여넣기 등
  e.preventDefault();
  const text = (e.clipboardData?.getData('text') || '').trim();
  if (!text) return;
  input.setRangeText(text, input.selectionStart, input.selectionEnd, 'end');
  if (/^\S+$/.test(input.value.trim())) $('go').click();
});
