import { validateHostLists, MAX_PROTECTION_RULES, MAX_SIGNATURE_RULES, MAX_BLOCK_HOSTS } from '../../core/dnr.js';
import { esc } from '../../shared/render.js';
const $ = id => document.getElementById(id);
const STALE_MS = 3 * 24 * 60 * 60_000;

function parseHostList(value) {
  const out = [];
  for (const line of value.split('\n')) {
    const text = line.trim();
    if (!text) continue;
    let host;
    try {
      const url = new URL(/^[a-z]+:\/\//i.test(text) ? text : 'http://' + text);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error();
      host = url.hostname.toLowerCase().replace(/^www\./, '');
    } catch {
      throw new Error(`도메인 입력을 확인하세요: ${text.slice(0, 100)}`);
    }
    out.push(host);
  }
  return [...new Set(out)];
}

async function load() {
  const s = await chrome.storage.local.get(['realtime', 'allow', 'block']);
  $('realtime').checked = s.realtime !== false;
  $('allow').value = (s.allow || []).join('\n');
  $('block').value = (s.block || []).join('\n');
  await status();
}
async function status() {
  const s = await chrome.runtime.sendMessage({ type: 'status' });
  if (s?.error) { $('msg').textContent = s.error; return; }
  const m = s.feedMeta || {}, rs = s.ruleStats || {};
  const time = t => new Date(t).toLocaleString();
  $('rc').textContent = `DNR 적용 ${Number(s.ruleCount || 0).toLocaleString()} / ${MAX_PROTECTION_RULES.toLocaleString()}개` +
    ` (DB 자동 차단 ${Number(rs.signatureRules || 0).toLocaleString()} · 사용자 경고 ${Number(rs.userBlockRules || 0).toLocaleString()} · 허용 ${Number(rs.userAllowRules || 0).toLocaleString()})`;
  $('coverage').textContent = `DB block 상한 ${MAX_SIGNATURE_RULES.toLocaleString()}개 · 사용자 redirect 최대 ${MAX_BLOCK_HOSTS.toLocaleString()}개 · 고유 시그니처 ${Number(rs.candidateUrls || 0).toLocaleString()}개 중 자동 차단 ${Number(rs.signatureRules || 0).toLocaleString()}개` +
    ` · 한도 초과 ${Number(rs.quotaOverflowUrls || 0).toLocaleString()}개` +
    ` · 필터 표현 불가 ${Number(rs.unsupportedUrls || 0).toLocaleString()}개` +
    ` · 사용자 허용으로 제외 ${Number(rs.excludedByAllow || 0).toLocaleString()}개` +
    ` · 사용자 경고 규칙으로 처리 ${Number(rs.handledByUserBlock || 0).toLocaleString()}개` +
    ` · DNR 미반영 URL도 수동 검사에서는 조회 가능합니다. (사용자 허용 규칙이 추가되면 DB block 수가 줄어들 수 있음)`;
  const rows = Object.entries(s.counts || {}).filter(([k, n]) => k !== 'Demo' || n > 0)
    .map(([k, n]) => `<tr><td>${esc(k)}</td><td>${n.toLocaleString()}건</td></tr>`);
  if (m.generatedAt) rows.push(`<tr><td colspan="2" class="muted">데이터 생성 시각: ${esc(time(m.generatedAt))}</td></tr>`);
  if (m.lastSuccess) rows.push(`<tr><td colspan="2" class="muted">마지막 업데이트: ${esc(time(m.lastSuccess))}</td></tr>`);
  if (m.nextAt) rows.push(`<tr><td colspan="2" class="muted">다음 확인: ${esc(time(m.nextAt))}</td></tr>`);
  if (m.ruleError) rows.push(`<tr><td colspan="2" class="err">차단 규칙 적용 오류: ${esc(m.ruleError)}</td></tr>`);
  if (m.lastError) rows.push(`<tr><td colspan="2" class="err">최근 오류: ${esc(m.lastError)} (기존 데이터 유지 중)</td></tr>`);
  $('tbl').innerHTML = rows.join('') || '<tr><td class="muted">아직 업데이트하지 않았습니다.</td></tr>';
  const notes = [];
  if (m.demoOnly) notes.push('공개 피드에는 시연용(.test) 데이터만 포함돼 있습니다.');
  if (m.generatedAt && Date.now() - Date.parse(m.generatedAt) > STALE_MS) notes.push('공개 데이터가 3일 이상 갱신되지 않았습니다.');
  $('note').textContent = notes.join(' ');
}

async function save() {
  $('msg').textContent = '';
  const button = $('save');
  button.disabled = true;
  const previous = await chrome.storage.local.get(['realtime', 'allow', 'block']);
  try {
    const next = {
      realtime: $('realtime').checked,
      allow: parseHostList($('allow').value),
      block: parseHostList($('block').value)
    };
    validateHostLists(next.allow, next.block);
    await chrome.storage.local.set(next);
    const result = await chrome.runtime.sendMessage({ type: 'rebuild' });
    if (result?.error) throw new Error(result.error);
    $('msg').textContent = '설정 및 실시간 보호 규칙을 적용했습니다.';
    await load();
    return true;
  } catch (e) {
    // DNR API가 규칙을 거부하면 구 설정으로 복구하여 저장 상태와 실제 보호 규칙을 일치시킨다.
    await chrome.storage.local.set(previous);
    $('msg').textContent = '적용 실패: ' + (e.message || e);
    return false;
  } finally { button.disabled = false; }
}
$('save').onclick = save;
$('sync').onclick = async () => {
  $('sync').disabled = true;
  $('sync').textContent = '업데이트 중…';
  try {
    if (!await save()) return;
    const result = await chrome.runtime.sendMessage({ type: 'sync', force: true });
    if (result?.error) $('msg').textContent = '업데이트 오류: ' + result.error;
    await status();
  } catch (e) {
    $('msg').textContent = String(e.message || e);
  } finally { $('sync').disabled = false; $('sync').textContent = '지금 업데이트'; }
};
load().catch(e => { $('msg').textContent = String(e.message || e); });
