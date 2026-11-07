import { resultHTML } from '../../shared/render.js';

const el = id => document.getElementById(id);
const input = el('urlInput');
const scanButton = el('scanButton');
const syncButton = el('refreshButton');
const resultSection = el('resultSection');
const output = el('resultContent');
let ready = false;
let working = false;
let nextId = 0;
let pendingId = null;

const worker = new Worker(new URL('./scan-worker.js', import.meta.url), { type: 'module' });
function feedStatus(text, problem = false) {
  el('syncStatus').textContent = text;
  el('healthText').textContent = problem ? '연결 오류' : ready ? '데이터 준비됨' : '데이터 연결 중';
  el('healthBadge').classList.toggle('error', problem);
  scanButton.disabled = !ready || working;
}
function localDate(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '확인 불가' : date.toLocaleString('ko-KR');
}

worker.onmessage = event => {
  const msg = event.data || {};
  if (msg.type === 'loading') {
    if (!msg.hasPrevious) ready = false;
    syncButton.disabled = true;
    feedStatus(msg.hasPrevious ? '새 시그니처 확인 중 (이전 데이터 사용 가능)' : '시그니처를 불러오고 있습니다.');
  } else if (msg.type === 'ready') {
    ready = true;
    syncButton.disabled = false;
    el('signatureCount').textContent = msg.count.toLocaleString('ko-KR');
    el('sourceCount').textContent = Object.keys(msg.sources).length.toLocaleString('ko-KR');
    el('lastUpdated').textContent = localDate(msg.generatedAt);
    el('datasetType').textContent = msg.demoOnly ? '시연용 데이터' : '공개 위협 피드';
    el('datasetType').title = msg.demoOnly ? '현재 피드에는 실제 위협 DB가 아닌 .test 데모 URL만 포함되어 있습니다.' : '공개 시그니처 피드';
    feedStatus(msg.demoOnly ? '데모 시그니처 준비됨 · 실제 탐지 데이터 아님' : `시그니처 준비됨 · 고유 URL ${msg.uniqueCount.toLocaleString('ko-KR')}개`);
  } else if (msg.type === 'load-error') {
    ready = Boolean(msg.hasPrevious);
    syncButton.disabled = false;
    feedStatus(msg.hasPrevious
      ? `갱신 실패 — 이전 데이터로 검사합니다: ${msg.error}`
      : `시그니처 로드 실패: ${msg.error}`, true);
  } else if (msg.type === 'check-result') {
    if (msg.id !== pendingId) return;
    working = false;
    pendingId = null;
    scanButton.disabled = !ready;
    scanButton.querySelector('span').textContent = 'URL 검사';
    if (msg.error) {
      output.textContent = `검사할 수 없습니다: ${msg.error}`;
      return;
    }
    const result = msg.result;
    output.innerHTML = resultHTML(result);
    if (result?.url) el('resultUrl').textContent = result.url;
    // 공유 렌더러가 표시한 시그니처 결과에 대해 확장 프로그램과 같은 주의 문구를 유지한다.
  }
};
worker.onerror = e => {
  console.error('검사 워커 오류:', e);
  working = false; ready = false;
  syncButton.disabled = false;
  feedStatus('검사 모듈을 불러오지 못했습니다. 새로고침하거나 서버 설정을 확인하세요.', true);
  if (pendingId !== null) output.textContent = '검사 모듈 오류가 발생했습니다.';
};

function scan(raw) {
  const url = String(raw || '').trim();
  if (!url) { input.focus(); return; }
  if (!ready || working) return;
  working = true;
  const id = ++nextId;
  pendingId = id;
  scanButton.disabled = true;
  scanButton.querySelector('span').textContent = '검사 중...';
  resultSection.hidden = false;
  el('resultTime').textContent = new Date().toLocaleString('ko-KR');
  el('resultUrl').textContent = url;
  output.innerHTML = '<p class="loading-line">시그니처와 URL 특징을 분석하고 있습니다...</p>';
  worker.postMessage({ type: 'check', id, url });
  resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

el('scanForm').addEventListener('submit', event => {
  event.preventDefault();
  scan(input.value);
});
syncButton.addEventListener('click', () => worker.postMessage({ type: 'refresh' }));
document.querySelectorAll('[data-sample]').forEach(button => {
  button.addEventListener('click', () => {
    input.value = button.dataset.sample;
    if (ready) scan(input.value);
    else input.focus();
  });
});

// 예외: file://은 모듈 Worker와 fetch의 브라우저 보안 정책상 지원하지 않는다.
if (location.protocol === 'file:') {
  feedStatus('HTML 파일을 직접 열지 말고 로컬 웹서버 또는 GitHub Pages에서 실행하세요.', true);
}
