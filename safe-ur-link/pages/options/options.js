import { hostOf } from '../../core/common.js';
import { esc } from '../../shared/render.js';
const $ = id => document.getElementById(id);
const lines = t => [...new Set(t.split('\n').map(x => x.trim()).filter(Boolean).map(x => hostOf(/^[a-z]+:\/\//i.test(x) ? x : 'http://' + x)).filter(Boolean))];
async function load() {
  const s = await chrome.storage.local.get(['realtime', 'allow', 'block']);
  $('realtime').checked = s.realtime !== false;
  $('allow').value = (s.allow || []).join('\n'); $('block').value = (s.block || []).join('\n');
  await status();
}
async function status() {
  const s = await chrome.runtime.sendMessage({ type: 'status' }), r = s.remoteState || {};
  $('rc').textContent = `적용 중인 차단 규칙 ${(s.ruleCount || 0).toLocaleString()}개`;
  $('feedUrl').textContent = `배포 주소: ${s.feedUrl || '미설정'}`;
  const time = t => t ? new Date(t).toLocaleString() : '없음';
  const stale = !!(r.generatedAt && Date.now() - Date.parse(r.generatedAt) > 48 * 3600_000);
  $('feedStatus').textContent = r.error ? `업데이트 실패: ${r.error} · 기존 DB 유지` : r.generatedAt
    ? `배포 시각: ${time(r.generatedAt)} · 다음 확인: ${time(r.nextAt)}${r.demoOnly ? ' · 시연용 데이터만 포함' : ''}${stale ? ' · 오래된 데이터' : ''}` : '아직 업데이트 전';
  $('feedStatus').className = r.error || stale ? 'err' : 'muted';
  $('tbl').innerHTML = Object.entries(s.counts || {}).map(([name, n]) => `<tr><td>${esc(name)}</td><td>${n.toLocaleString()}건</td></tr>`).join('');
}
$('save').onclick = async () => {
  $('msg').textContent = '저장 중…';
  await chrome.storage.local.set({ realtime: $('realtime').checked, allow: lines($('allow').value), block: lines($('block').value) });
  const r = await chrome.runtime.sendMessage({ type: 'rebuild' });
  $('msg').textContent = r?.error ? `오류: ${r.error}` : '설정 저장 완료';
  await status();
};
$('sync').onclick = async () => {
  const btn = $('sync'); btn.disabled = true; btn.textContent = '업데이트 중…';
  try { await chrome.runtime.sendMessage({ type: 'sync' }); await status(); }
  finally { btn.disabled = false; btn.textContent = '지금 업데이트'; }
};
load();
