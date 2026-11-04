import { normalizeUrl } from '../../core/common.js';
import { resultHTML } from '../../shared/render.js';

// 사용자 차단 도메인은 DNR regexSubstitution으로 원본 URL을 # 뒤에 붙이고,
// 외부 시그니처 URL은 ?u=... 매개변수로 전달한다.
const paramTarget = new URLSearchParams(location.search).get('u');
const rawTarget = paramTarget || location.hash.slice(1);
const target = normalizeUrl(rawTarget);
const $ = id => document.getElementById(id);
$('url').textContent = target || '원래 요청 URL을 확인할 수 없습니다.';

if (!target) {
  $('info').textContent = '올바른 HTTP/HTTPS 주소가 없어 접속을 진행할 수 없습니다.';
  $('proceed').disabled = true;
} else {
  chrome.runtime.sendMessage({ type: 'check', url: target })
    .then(r => { $('info').innerHTML = resultHTML(r); })
    .catch(() => { $('info').textContent = 'URL의 상세 분석을 불러오지 못했습니다. 접속은 계속 차단된 상태입니다.'; });
}

$('back').onclick = () => {
  if (history.length > 1) history.back();
  else chrome.runtime.sendMessage({ type: 'goSafe' });
};

$('proceed').onclick = async () => {
  if (!target) return;
  $('proceed').disabled = true;
  $('error').textContent = '';
  try {
    const result = await chrome.runtime.sendMessage({ type: 'allowOnce', url: target });
    if (result?.error) throw new Error(result.error);
    // 규칙 등록이 정상 종료된 경우에만 원본 URL로 접속
    location.replace(target);
  } catch (e) {
    $('error').textContent = '예외 규칙 추가에 실패했습니다: ' + (e.message || e);
    $('proceed').disabled = false;
  }
};
