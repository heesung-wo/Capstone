import { normalizeUrl, hostOf, heuristics, externalScore, verdictOf } from '../core/common.js';
import * as db from '../core/db.js';
import { SIGNATURE_FEED_URL, REFRESH_INTERVAL_MS } from '../core/config.js';
import { downloadFeed, SOURCES } from '../core/remote-feed.js';

const DEFAULTS = { realtime: true, allow: [], block: [] };
const RETRY_MS = 60 * 60_000, MANUAL_COOLDOWN_MS = 60_000;
const MAX_FEED_RULES = 20000, USER_BASE = 100000;
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

// ── 시그니처 동기화: 개발자가 GitHub Pages에 공개한 signatures.json 하나만 내려받는다.
// 외부 위협 정보 API와 비밀 키는 GitHub Actions에서만 사용되며, 확장 프로그램에는 키가 없다.
// 실패하거나 형식이 잘못되면 기존 IndexedDB 데이터는 그대로 유지한다.
// chrome.storage.local에는 작은 갱신 상태(feedMeta)만 기록한다.
let runningSync;
async function performSync(force) {
  const { feedMeta = {} } = await chrome.storage.local.get('feedMeta');
  const now = Date.now();
  if (!force && feedMeta.nextAt && now < feedMeta.nextAt) return { ok: !feedMeta.lastError, skipped: true };
  if (force && feedMeta.lastAttempt && now - feedMeta.lastAttempt < MANUAL_COOLDOWN_MS) return { ok: !feedMeta.lastError, skipped: true, cooldown: true };
  try {
    const feed = await downloadFeed(SIGNATURE_FEED_URL);
    const hasData = Object.values(await db.countBySource()).some(n => n > 0);
    let changed = false;
    if (feed.generatedAt !== feedMeta.generatedAt || !hasData) {
      const bySource = Object.fromEntries(SOURCES.map(n => [n, []]));
      for (const r of feed.records) bySource[r.source].push({ url: r.url, meta: r.meta });
      for (const n of SOURCES) await db.replaceSource(n, bySource[n]);   // 피드에 없는 소스는 비운다
      changed = true;
    }
    await chrome.storage.local.set({ feedMeta: {
      generatedAt: feed.generatedAt, lastAttempt: now, lastSuccess: Date.now(),
      nextAt: Date.now() + REFRESH_INTERVAL_MS, count: feed.records.length, demoOnly: feed.demoOnly
    } });
    if (changed) await rebuildRules();
    return { ok: true, changed, count: feed.records.length };
  } catch (e) {
    const error = String(e.message || e);
    await chrome.storage.local.set({ feedMeta: { ...feedMeta, lastAttempt: now, nextAt: now + RETRY_MS, lastError: error } });
    return { ok: false, error };
  }
}
export function sync(force = false) {
  if (!runningSync) runningSync = performSync(force).finally(() => { runningSync = undefined; });
  return runningSync;
}

// ── DNR 규칙: 피드 규칙(id 1..), 사용자 규칙(id 100001..)
export async function rebuildRules() {
  const s = await getSettings();
  const old = (await chrome.declarativeNetRequest.getDynamicRules()).map(r => r.id);
  const add = [];
  if (s.realtime) {
    const groups = new Map();
    for (const r of await db.all()) (groups.get(r.url) || groups.set(r.url, []).get(r.url)).push(r);
    const urls = [...groups.entries()].filter(([u]) => !/[*^|]/.test(u))
      .sort((a, b) => new Set(b[1].map(x => x.source)).size - new Set(a[1].map(x => x.source)).size)
      .slice(0, MAX_FEED_RULES).map(([u]) => u);
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
  // 이전 버전(사용자가 API 키를 직접 입력)에서 저장된 키와 상태를 제거한다.
  chrome.storage.local.remove(['authKey', 'phishKey', 'feedState', 'syncStatus']);
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
    sync: () => sync(msg.force === true),
    rebuild: () => rebuildRules(),
    allowOnce: () => allowOnce(msg.url),
    goSafe: () => chrome.tabs.update(sender.tab.id, { url: 'chrome://newtab/' }),
    status: async () => ({ ...(await chrome.storage.local.get(['feedMeta', 'ruleCount'])), counts: await db.countBySource() })
  }[msg.type];
  if (!run) return false;
  run().then(reply, e => reply({ error: String(e.message || e) }));
  return true;
});
