import { normalizeUrl, hostOf, heuristics, externalScore, verdictOf } from '../core/common.js';
import * as db from '../core/db.js';
import { FEEDS, REFRESH_MS, PHISHTANK_ANONYMOUS_MS } from '../core/feeds.js';

const DEFAULTS = { authKey: '', phishKey: '', realtime: true, allow: [], block: [] };
// Chrome DNR redirect 는 안전하지 않은 동적 규칙으로 분류되어 최대 5000개.
// 사용자 차단 목록/브라우저 차이를 고려해 4800개로 제한한다.
const MAX_REDIRECT_RULES = 4800, USER_BASE = 100000;
const getSettings = async () => ({ ...DEFAULTS, ...(await chrome.storage.local.get(Object.keys(DEFAULTS))) });
const warnUrl = u => chrome.runtime.getURL('pages/warning/warning.html') + '?u=' + encodeURIComponent(u);
const main = { resourceTypes: ['main_frame'] };

// ── URL 검사: 정규화 → 사용자 목록 → 로컬 DB → 외부 평가 → 휴리스틱 → 판정
export async function check(raw) {
  const url = normalizeUrl(raw);
  if (!url) return { error: 'http/https URL만 검사할 수 있습니다.' };
  const host = hostOf(url), s = await getSettings();
  const base = { url, host, checkedAt: Date.now() };
  if (s.allow.includes(host)) return { ...base, verdict: 'No Threat Detected', score: 0, userList: 'allow', sources: [], reasons: [{ points: 0, text: '사용자 허용 목록에 등록된 도메인입니다' }] };
  if (s.block.includes(host)) return { ...base, verdict: 'Malicious', score: 100, userList: 'block', sources: [], reasons: [{ points: 0, text: '사용자 차단 목록에 등록된 도메인입니다' }] };

  const records = await db.lookup(url);
  const ext = externalScore(records), heur = heuristics(raw);
  const score = Math.min(ext.score + heur.score, 100);
  return {
    ...base, verdict: verdictOf(records.length > 0, score), score,
    externalScore: ext.score, heuristicScore: heur.score,
    sources: [...new Set(records.map(r => r.source))],
    threats: [...new Set(records.map(r => r.meta?.threat).filter(Boolean))],
    reasons: [...ext.reasons.map(r => ({ ...r, kind: 'external' })), ...heur.reasons.map(r => ({ ...r, kind: 'heuristic' }))]
  };
}

// ── 데이터 수집·정규화·저장. 성공한 피드만 교체하고, 실패 시 기존 DB는 유지한다.
// chrome.storage.local에는 작은 갱신 상태만 기록한다 (실제 URL 목록은 IndexedDB).
let runningSync;
const smallTag = text => { // 캐시 무효화 감지용, 비밀 키 자체를 저장하지 않음
  let h = 2166136261;
  for (const c of text) h = Math.imul(h ^ c.charCodeAt(0), 16777619);
  return (h >>> 0).toString(16);
};
function retryDelay(error) {
  const raw = error?.retryAfter;
  const secs = Number(raw);
  const date = Date.parse(raw || '');
  const serverDelay = Number.isFinite(secs) && secs >= 0 ? secs * 1000
    : Number.isFinite(date) ? Math.max(0, date - Date.now()) : 0;
  const isLimit = [429, 509].includes(error?.httpStatus);
  const isAccessDenied = [401, 403].includes(error?.httpStatus);
  // 같은 인증값으로 401/403을 매시간 재시도하지 않는다. 키가 바뀌면 즉시 재시도 가능.
  return Math.max(60 * 60_000, serverDelay, isAccessDenied ? 24 * 60 * 60_000 : 0, isLimit ? 6 * 60 * 60_000 : 0);
}

function friendlyFeedError(name, error) {
  const status = error?.httpStatus;
  if (name === 'URLhaus' && status === 401) return 'HTTP 401 · abuse.ch Auth-Key 인증 실패: 키 발급/복사·유효성 확인 (재시도: 키 교체 시 즉시)';
  if (name === 'ThreatFox' && status === 403) return 'HTTP 403 · 서버 접근 거부: 키 권한, API 정책 또는 IP/보안 차단 확인';
  if (status === 401) return 'HTTP 401 · API 인증 실패: 입력한 키 확인';
  if (status === 403) return 'HTTP 403 · API 접근 거부: 제공자 계정/권한 또는 보안 정책 확인';
  if (name === 'PhishTank' && error?.code === 'NETWORK_ERROR')
    return '네트워크 연결 실패 · 확장 프로그램에서 PhishTank 서버에 연결되지 않음 (개발자 도구 확인 / JSON 파일 수동 가져오기 가능)';
  return String(error?.message || error);
}

async function performSync() {
  const s = await getSettings(), results = {};
  const previous = (await chrome.storage.local.get({ feedState: {} })).feedState;
  const feedState = { ...previous };
  let changed = false;
  await Promise.all(Object.entries(FEEDS).map(async ([name, fn]) => {
    const key = name === 'PhishTank' ? s.phishKey : (['URLhaus', 'ThreatFox'].includes(name) ? s.authKey : '');
    const tag = smallTag(key || '');
    const old = previous[name] || {};
    const interval = name === 'PhishTank' && !s.phishKey ? PHISHTANK_ANONYMOUS_MS : REFRESH_MS[name];
    if (['URLhaus', 'ThreatFox'].includes(name) && !s.authKey) {
      results[name] = { ok: false, skipped: true, error: '무료 abuse.ch Auth-Key가 필요합니다.', count: old.count || 0 };
      return;
    }
    if (old.credentialTag === tag && old.nextAt && Date.now() < old.nextAt) {
      results[name] = { ok: !!old.lastSuccess && !old.lastError, skipped: true, count: old.count || 0,
        nextAt: old.nextAt, error: old.lastError || undefined };
      return;
    }
    const began = Date.now();
    try {
      const seen = new Map();
      for (const it of await fn(s)) {
        const n = normalizeUrl(it.url);
        if (n && !seen.has(n)) seen.set(n, { url: n, meta: it.meta });
      }
      // 응답 형식 변경이나 차단 페이지 때문에 전체 DB가 실수로 비워지지 않도록 방어한다.
      if (!seen.size && name !== 'ThreatFox') throw new Error('정규화 가능한 URL이 없습니다. 기존 데이터 유지');
      await db.replaceSource(name, [...seen.values()]);
      changed = true;
      feedState[name] = { lastAttempt: began, lastSuccess: Date.now(), count: seen.size,
        credentialTag: tag, nextAt: Date.now() + interval };
      results[name] = { ok: true, count: seen.size, nextAt: feedState[name].nextAt };
    } catch (e) {
      // 차단/호출 제한/네트워크 오류에도 마지막 정상 데이터는 남겨둔다.
      const delay = Math.max(interval, retryDelay(e));
      feedState[name] = { ...old, lastAttempt: began, credentialTag: tag,
        nextAt: Date.now() + delay, lastError: friendlyFeedError(name, e) };
      results[name] = { ok: false, error: friendlyFeedError(name, e), count: old.count || 0,
        nextAt: feedState[name].nextAt };
    }
  }));
  await chrome.storage.local.set({ feedState, syncStatus: { time: Date.now(), results } });
  if (changed) await rebuildRules();
  return results;
}
async function importComplete(source, count) {
  if (source !== 'PhishTank' || !Number.isInteger(count) || count <= 0) throw new Error('올바르지 않은 가져오기 요청');
  const s = await getSettings();
  const tag = smallTag(s.phishKey || '');
  const stored = await chrome.storage.local.get({ feedState: {}, syncStatus: {} });
  const nextAt = Date.now() + (s.phishKey ? REFRESH_MS.PhishTank : PHISHTANK_ANONYMOUS_MS);
  const state = { ...stored.feedState, PhishTank: {
    lastSuccess: Date.now(), count, credentialTag: tag, nextAt, importMethod: 'file'
  } };
  const status = { time: Date.now(), results: {
    ...stored.syncStatus.results, PhishTank: { ok: true, count, nextAt, imported: true }
  } };
  await chrome.storage.local.set({ feedState: state, syncStatus: status });
  await rebuildRules();
  return { success: true, count };
}

export function sync() {
  if (!runningSync) runningSync = performSync().finally(() => { runningSync = undefined; });
  return runningSync;
}

// ── DNR 규칙: 피드 규칙(id 1..), 사용자 규칙(id 100001..)
export async function rebuildRules() {
  const s = await getSettings();
  const old = (await chrome.declarativeNetRequest.getDynamicRules()).map(r => r.id);
  const add = [];
  if (s.block.length > MAX_REDIRECT_RULES) throw new Error(`차단 목록이 허용 규칙 수(${MAX_REDIRECT_RULES})를 초과했습니다.`);
  if (s.realtime) {
    const groups = new Map();
    for (const r of await db.all()) (groups.get(r.url) || groups.set(r.url, []).get(r.url)).push(r);
    const urls = [...groups.entries()].filter(([u]) => !/[*^|]/.test(u))
      .sort((a, b) => new Set(b[1].map(x => x.source)).size - new Set(a[1].map(x => x.source)).size)
      .slice(0, MAX_REDIRECT_RULES - s.block.length).map(([u]) => u);
    urls.forEach((u, i) => add.push({
      id: i + 1, priority: 1, action: { type: 'redirect', redirect: { url: warnUrl(u) } },
      condition: { urlFilter: `|${u}|`, isUrlFilterCaseSensitive: true, ...main }
    }));
  }
  let id = USER_BASE;
  for (const h of s.block) add.push({ id: ++id, priority: 2, action: { type: 'redirect', redirect: { url: warnUrl('http://' + h + '/') } }, condition: { urlFilter: `||${h}^`, ...main } });
  for (const h of s.allow) add.push({ id: ++id, priority: 3, action: { type: 'allow' }, condition: { urlFilter: `||${h}^`, ...main } });
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: old, addRules: add });
  await chrome.storage.local.set({ ruleCount: add.length });
}

async function allowOnce(url) {   // 이번 브라우저 세션 동안만 허용 (session rule)
  const id = Date.now() % 1e9;
  await chrome.declarativeNetRequest.updateSessionRules({
    addRules: [{ id, priority: 10, action: { type: 'allow' }, condition: { urlFilter: `|${url}|`, isUrlFilterCaseSensitive: true, ...main } }]
  });
}

// ── 이벤트
const ensureAlarm = () => chrome.alarms.create('sync', { periodInMinutes: 60 });
chrome.runtime.onInstalled.addListener(() => {
  ensureAlarm();
  chrome.contextMenus.create({ id: 'check', title: 'Safe UR Link로 검사', contexts: ['link', 'selection'] });
  sync();
});
chrome.runtime.onStartup.addListener(() => { ensureAlarm(); sync(); });
chrome.alarms.onAlarm.addListener(a => a.name === 'sync' && sync());

chrome.contextMenus.onClicked.addListener(async info => {
  const r = await check(info.linkUrl || info.selectionText);
  const labels = { Malicious: '악성 URL', Suspicious: '주의 필요', 'No Threat Detected': '위협 미탐지' };
  chrome.notifications.create({
    type: 'basic', iconUrl: 'assets/icons/128.png', title: r.error ? 'Safe UR Link' : `${labels[r.verdict]} · 위험 점수 ${r.score}/100`,
    message: r.error || (r.reasons[0]?.text || '탐지된 위험 요소가 없습니다. (안전을 보증하지는 않습니다)')
  });
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const run = {
    check: () => check(msg.url),
    sync: () => sync(),
    rebuild: () => rebuildRules(),
    importComplete: () => importComplete(msg.source, msg.count),
    allowOnce: () => allowOnce(msg.url),
    goSafe: () => chrome.tabs.update(sender.tab.id, { url: 'chrome://newtab/' }),
    status: async () => ({ ...(await chrome.storage.local.get(['syncStatus', 'ruleCount'])), counts: await db.countBySource() })
  }[msg.type];
  if (!run) return false;
  run().then(reply, e => reply({ error: String(e.message || e) }));
  return true;
});
