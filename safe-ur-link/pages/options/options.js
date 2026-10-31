import { hostOf } from '../../core/common.js';
import { esc } from '../../shared/render.js';
const $ = id => document.getElementById(id);
const lines = t => [...new Set(t.split('\n').map(x => x.trim()).filter(Boolean).map(x => hostOf(/^[a-z]+:\/\//i.test(x) ? x : 'http://' + x)).filter(Boolean))];
async function load() {
  const s = await chrome.storage.local.get(['authKey', 'phishKey', 'realtime', 'allow', 'block']);
  $('authKey').value = s.authKey || ''; $('phishKey').value = s.phishKey || '';
  $('realtime').checked = s.realtime !== false;
  $('allow').value = (s.allow || []).join('\n'); $('block').value = (s.block || []).join('\n');
  status();
}
async function status() {
  const s = await chrome.runtime.sendMessage({ type: 'status' }), res = s.syncStatus?.results || {};
  $('rc').textContent = `적용 중인 차단 규칙 ${(s.ruleCount || 0).toLocaleString()}개`;
  $('tbl').innerHTML = Object.entries(s.counts || {}).map(([k, n]) => {
    const r = res[k];
    const date = r?.nextAt ? ` · 다음 확인 ${new Date(r.nextAt).toLocaleString()}` : '';
    const msg = !r ? '아직 검사 전' : r.ok
      ? (r.skipped ? '갱신 간격 이내 · 기존 DB 사용' : '수집 성공') + date
      : (r.error || '수집 실패') + date;
    return `<tr><td>${k}</td><td>${n.toLocaleString()}건</td><td class="${r?.ok === false ? 'err' : 'muted'}">${esc(msg)}</td></tr>`;
  }).join('') + (s.syncStatus
    ? `<tr><td colspan="3" class="muted">마지막 확인: ${new Date(s.syncStatus.time).toLocaleString()}</td></tr>` : '');
}
$('save').onclick = async () => {
  await chrome.storage.local.set({ authKey: $('authKey').value.trim(), phishKey: $('phishKey').value.trim(), realtime: $('realtime').checked, allow: lines($('allow').value), block: lines($('block').value) });
  await chrome.runtime.sendMessage({ type: 'rebuild' }); await load(); $('msg').textContent = '저장했습니다';
};
$('sync').onclick = async () => {
  $('sync').disabled = true; $('sync').textContent = '업데이트 중…';
  await $('save').onclick(); await chrome.runtime.sendMessage({ type: 'sync' });
  $('sync').disabled = false; $('sync').textContent = '지금 업데이트'; await status();
};
load();
