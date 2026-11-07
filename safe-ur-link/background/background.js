import { normalizeUrl, hostOf } from '../core/common.js';
import { evaluateUrl } from '../core/scan.js';
import * as db from '../core/db.js';
import { SIGNATURE_FEED_URL, REFRESH_INTERVAL_MS } from '../core/config.js';
import { downloadFeed } from '../core/remote-feed.js';
import { buildProtectionRules, hostMatches, DEMO_SIGNATURES, sessionAllowCondition } from '../core/dnr.js';
import { registerContextMenu, targetFromContext, resultPageUrl } from '../core/context-menu.js';

const DEFAULTS = { realtime: true, allow: [], block: [] };
const RETRY_MS = 60 * 60_000, MANUAL_COOLDOWN_MS = 60_000;
// 다운로드된 악성 시그니처는 block, 사용자 차단 도메인만 redirect (Chrome 121+ 총 30,000개 한도).
const getSettings = async () => ({ ...DEFAULTS, ...(await chrome.storage.local.get(Object.keys(DEFAULTS))) });
const WARNING_PAGE = 'pages/warning/warning.html';
let registeringMenu;
function ensureContextMenu() {
  if (!registeringMenu) {
    registeringMenu = registerContextMenu(chrome).finally(() => { registeringMenu = undefined; });
  }
  return registeringMenu;
}

// ── URL 검사: 정규화 → 사용자 목록 → 로컬 DB → 외부 평가 → 휴리스틱 → 판정
export async function check(raw) {
  const url = normalizeUrl(raw);
  if (!url) return { error: 'http/https URL만 검사할 수 있습니다.' };
  const host = hostOf(url), s = await getSettings();
  // 사용자 목록이 우선하는 기존 정책 유지. 목록에 있으면 IndexedDB 접근 불필요.
  if (s.allow.some(entry => hostMatches(host, entry)) ||
      s.block.some(entry => hostMatches(host, entry))) {
    return evaluateUrl(raw, [], s);
  }

  const records = await db.lookup(url);
  if (DEMO_SIGNATURES.includes(url) && !records.length) {
    // 실제 피드를 수집한 뒤에는 시연용 내장 URL을 악성 판정하지 않는다.
    const counts = await db.countBySource();
    if (!Object.values(counts).some(n => n > 0)) records.push({ source: 'Demo', url, meta: {} });
  }
  return evaluateUrl(raw, records, s);
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
      // 기존 DB 레코드를 삭제하지 않고 변경된 시그니처를 추가/갱신한다.
      // 서버의 소스별 실패 시 해당 소스의 마지막 데이터는 그대로 남는다.
      const hasReal = (await db.countBySource());
      const realCount = Object.entries(hasReal).filter(([key]) => key !== 'Demo').reduce((sum, [, count]) => sum + count, 0);
      if (!(feed.demoOnly && realCount)) {
        await db.mergeRecords(feed.records);
        await db.deactivateMissing(feed.records, feed.sourceStatus, feedMeta.generatedAt);
      }
      if (!feed.demoOnly && feed.records.length) await db.clearDemo();
      changed = true;
    }
    await chrome.storage.local.set({ feedMeta: {
      generatedAt: feed.generatedAt, lastAttempt: now, lastSuccess: Date.now(),
      nextAt: Date.now() + REFRESH_INTERVAL_MS, count: feed.records.length, demoOnly: feed.demoOnly, sourceStatus: feed.sourceStatus
    } });
    let ruleError;
    if (changed || feedMeta.ruleError) {
      try { await rebuildRules(); } catch (e) { ruleError = String(e.message || e); }
    }
    await chrome.storage.local.set({ feedMeta: { ...(await chrome.storage.local.get('feedMeta')).feedMeta, ruleError } });
    return { ok: !ruleError, changed, count: feed.records.length, error: ruleError };
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

// ── DNR 규칙 생성 및 적용. 업데이트가 겹치면 직렬화하여 오래된 데이터가 덮어쓰지 않게 한다.
let rulesQueue = Promise.resolve();
export function rebuildRules() {
  const task = rulesQueue.then(async () => {
    const s = await getSettings();
    const { rules, stats } = buildProtectionRules(
      s, await db.all(), chrome.runtime.getURL(WARNING_PAGE)
    );
    const old = (await chrome.declarativeNetRequest.getDynamicRules()).map(r => r.id);
    // DNR 변경은 원자적으로 적용된다. 실패하면 기존 정상 규칙이 그대로 남는다.
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: old, addRules: rules });
    await chrome.storage.local.set({ ruleCount: rules.length, ruleStats: stats });
    return stats;
  });
  rulesQueue = task.catch(() => {});
  return task;
}

// 이번 브라우저 세션에서 '해당 탭 + 정확한 URL'만 예외 허용.
// 사용자 차단 도메인의 모든 경로를 풀어주는 방식이 아니다.
async function allowOnce(raw, tabId) {
  const condition = sessionAllowCondition(raw, tabId);
  const dnr = chrome.declarativeNetRequest;
  const existing = await dnr.getSessionRules();
  const same = existing.find(rule => rule.action.type === 'allow' &&
    JSON.stringify(rule.condition) === JSON.stringify(condition));
  if (same) return { ok: true, reused: true };
  if (existing.length >= (dnr.MAX_NUMBER_OF_SESSION_RULES || 5000)) {
    throw new Error('세션 허용 규칙 한도를 초과했습니다. 브라우저를 다시 시작해 주세요.');
  }
  const id = Math.max(0, ...existing.map(r => r.id)) + 1;
  await dnr.updateSessionRules({
    addRules: [{ id, priority: 100, action: { type: 'allow' }, condition }]
  });
  return { ok: true, reused: false };
}

// ── 이벤트
const ensureAlarm = () => chrome.alarms.create('sync', { periodInMinutes: 60 });
chrome.runtime.onInstalled.addListener(() => {
  // 이전 버전(사용자가 API 키를 직접 입력)에서 저장된 키와 상태를 제거한다.
  chrome.storage.local.remove(['authKey', 'phishKey', 'feedState', 'syncStatus']);
  ensureAlarm();
  ensureContextMenu().catch(console.error);
  rebuildRules().catch(console.error);
  sync();
});
chrome.runtime.onStartup.addListener(() => {
  ensureAlarm();
  ensureContextMenu().catch(console.error); // 메뉴가 누락되었어도 브라우저 시작 시 복구
  rebuildRules().catch(console.error);
  sync();
});
chrome.alarms.onAlarm.addListener(a => a.name === 'sync' && sync());

chrome.contextMenus.onClicked.addListener((info) => {
  const target = targetFromContext(info);
  if (!target) return;
  // 선택 URL과 링크 목적지를 메뉴별로 명확히 분리해 전달한다.
  // 결과 페이지만 열고 위험 URL로 직접 이동하지 않는다.
  chrome.tabs.create({ url: resultPageUrl(chrome.runtime, target) })
    .catch(e => console.error('SafeURLink 우클릭 검사 결과 탭 열기 실패:', e));
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const run = {
    check: () => check(msg.url),
    sync: () => sync(msg.force === true),
    rebuild: () => rebuildRules(),
    allowOnce: () => allowOnce(msg.url, sender.tab?.id),
    goSafe: () => chrome.tabs.update(sender.tab.id, { url: 'chrome://newtab/' }),
    status: async () => ({ ...(await chrome.storage.local.get(['feedMeta', 'ruleCount', 'ruleStats'])), counts: await db.countBySource() })
  }[msg.type];
  if (!run) return false;
  run().then(reply, e => reply({ error: String(e.message || e) }));
  return true;
});
