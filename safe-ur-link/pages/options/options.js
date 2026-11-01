import { hostOf } from '../../core/common.js';
import { esc } from '../../shared/render.js';
const $ = id => document.getElementById(id);
const STALE_MS = 3 * 24 * 60 * 60_000;
const lines = t => [...new Set(t.split('\n').map(x => x.trim()).filter(Boolean).map(x => hostOf(/^[a-z]+:\/\//i.test(x) ? x : 'http://' + x)).filter(Boolean))];
async function load() {
  const s = await chrome.storage.local.get(['realtime', 'allow', 'block']);
  $('realtime').checked = s.realtime !== false;
  $('allow').value = (s.allow || []).join('\n'); $('block').value = (s.block || []).join('\n');
  status();
}
async function status() {
  const s = await chrome.runtime.sendMessage({ type: 'status' }), m = s.feedMeta || {};
  const time = t => new Date(t).toLocaleString();
  $('rc').textContent = `적용 중인 차단 규칙 ${(s.ruleCount || 0).toLocaleString()}개`;
  const rows = Object.entries(s.counts || {}).filter(([k, n]) => k !== 'Demo' || n > 0)
    .map(([k, n]) => `<tr><td>${esc(k)}</td><td>${n.toLocaleString()}건</td></tr>`);
  if (m.generatedAt) rows.push(`<tr><td colspan="2" class="muted">데이터 생성 시각: ${esc(time(m.generatedAt))}</td></tr>`);
  if (m.lastSuccess) rows.push(`<tr><td colspan="2" class="muted">마지막 업데이트: ${esc(time(m.lastSuccess))}</td></tr>`);
  if (m.nextAt) rows.push(`<tr><td colspan="2" class="muted">다음 확인: ${esc(time(m.nextAt))}</td></tr>`);
  if (m.lastError) rows.push(`<tr><td colspan="2" class="err">최근 오류: ${esc(m.lastError)} (기존 데이터 유지 중)</td></tr>`);
  $('tbl').innerHTML = rows.join('') || '<tr><td class="muted">아직 업데이트하지 않았습니다.</td></tr>';
  const notes = [];
  if (m.demoOnly) notes.push('현재 시연용 데이터(.test 주소)만 포함되어 있어 실제 악성 URL은 탐지하지 않습니다.');
  if (m.generatedAt && Date.now() - Date.parse(m.generatedAt) > STALE_MS) notes.push('공개된 데이터가 3일 이상 갱신되지 않았습니다.');
  $('note').textContent = notes.join(' ');
}
$('save').onclick = async () => {
  await chrome.storage.local.set({ realtime: $('realtime').checked, allow: lines($('allow').value), block: lines($('block').value) });
  await chrome.runtime.sendMessage({ type: 'rebuild' }); await load(); $('msg').textContent = '저장했습니다';
};
$('sync').onclick = async () => {
  $('sync').disabled = true; $('sync').textContent = '업데이트 중…';
  await $('save').onclick(); await chrome.runtime.sendMessage({ type: 'sync', force: true });
  $('sync').disabled = false; $('sync').textContent = '지금 업데이트'; await status();
};
load();
