import { resultHTML } from '../../shared/render.js';
import { isSelectedUrl } from '../../core/context-menu.js';

const params = new URLSearchParams(location.search);
const url = (params.get('url') || '').trim();
const mode = params.get('mode');
const target = document.getElementById('target');
const targetTitle = document.getElementById('targetTitle');
const result = document.getElementById('result');

if (mode === 'selection') targetTitle.textContent = '드래그해 선택한 URL 텍스트';
else targetTitle.textContent = '검사 대상 주소';
target.textContent = url || '(선택한 주소가 없습니다)';

async function scan() {
  if (!url) {
    result.textContent = '검사할 주소가 없습니다. URL을 드래그해 선택한 뒤 우클릭해 주세요.';
    return;
  }
  if (mode === 'selection' && !isSelectedUrl(url)) {
    result.textContent = '선택한 문구가 URL 형식이 아닙니다. 다른 링크의 주소로 대신 검사하지 않았습니다. https://... 형태의 주소 부분만 정확히 선택해 주세요.';
    return;
  }
  try {
    const response = await chrome.runtime.sendMessage({ type: 'check', url });
    result.innerHTML = resultHTML(response || { error: '검사 결과를 받지 못했습니다.' });
  } catch (e) {
    result.textContent = `검사 중 오류가 발생했습니다: ${String(e?.message || e)}`;
  }
}

scan();
