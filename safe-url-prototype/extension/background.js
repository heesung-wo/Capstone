"use strict";

const API = "http://127.0.0.1:3000/scan";
const SEED_HOSTS = ["phishing.test", "malware.test"];
const STORAGE_DEFAULTS = { blockHosts: [], allowHosts: [], knownBadUrls: [] };
const RULE_LIMIT = 1000;
let rebuildQueue = Promise.resolve();

function hostOf(input) {
  try {
    const u = input.includes("://") ? new URL(input) : new URL("https://" + input);
    if (!u.hostname || u.username || u.password || !["http:", "https:"].includes(u.protocol) || u.pathname !== "/" || u.search || u.hash || u.port) return null;
    return u.hostname.toLowerCase();
  } catch { return null; }
}
function urlOf(input) {
  try {
    const u = new URL(input);
    if (!["http:", "https:"].includes(u.protocol) || u.username || u.password) return null;
    u.hash = "";
    return u.href;
  } catch { return null; }
}
function escapeRegex(str) { return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function hostRegex(host) { return `^https?://${escapeRegex(host)}(?::[0-9]+)?(?:[/?].*)?$`; }

async function rebuildRules() {
  const state = await chrome.storage.local.get(STORAGE_DEFAULTS);
  const warningPrefix = chrome.runtime.getURL("warning.html#");
  let id = 1;
  const rules = [];
  const add = (regexFilter, priority, type, redirect = false) => {
    if (rules.length >= RULE_LIMIT) return;
    rules.push({ id: id++, priority,
      action: redirect ? { type, redirect: { regexSubstitution: warningPrefix + "\\0" } } : { type },
      condition: { regexFilter, resourceTypes: ["main_frame"] } });
  };
  for (const host of new Set([...SEED_HOSTS, ...state.blockHosts])) add(hostRegex(host), 10, "redirect", true);
  for (const url of new Set(state.knownBadUrls)) add(`^${escapeRegex(url)}$`, 10, "redirect", true);
  for (const host of new Set(state.allowHosts)) add(hostRegex(host), 20, "allow");
  const old = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: old.map(r => r.id), addRules: rules });
  return { count: rules.length, truncated: rules.length >= RULE_LIMIT };
}
function queueRebuild() { rebuildQueue = rebuildQueue.catch(() => {}).then(rebuildRules); return rebuildQueue; }

async function scanUrl(input) {
  const url = urlOf(input);
  if (!url) throw new Error("http/https URL을 입력하세요.");
  const response = await fetch(API, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }), signal: AbortSignal.timeout(10000) });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `Server HTTP ${response.status}`);
  if (result.sources?.phishTank?.malicious) {
    const state = await chrome.storage.local.get(STORAGE_DEFAULTS);
    if (!state.knownBadUrls.includes(url)) {
      await chrome.storage.local.set({ knownBadUrls: [...state.knownBadUrls, url].slice(-500) });
      await queueRebuild();
    }
  }
  return result;
}

async function editList(kind, input, add) {
  if (!["blockHosts", "allowHosts"].includes(kind)) throw new Error("잘못된 목록입니다.");
  const host = hostOf(input);
  if (!host) throw new Error("도메인만 입력하세요 (예: example.test).");
  const state = await chrome.storage.local.get(STORAGE_DEFAULTS);
  const list = new Set(state[kind]);
  if (add) list.add(host); else list.delete(host);
  await chrome.storage.local.set({ [kind]: [...list] });
  await queueRebuild();
  return chrome.storage.local.get(STORAGE_DEFAULTS);
}

async function proceedOnce(input, tabId) {
  const url = urlOf(input);
  if (!url || !Number.isInteger(tabId)) throw new Error("잘못된 이동 요청입니다.");
  const existing = await chrome.declarativeNetRequest.getSessionRules();
  const id = Math.max(199999, ...existing.map(r => r.id)) + 1;
  await chrome.declarativeNetRequest.updateSessionRules({ addRules: [{ id, priority: 30,
    action: { type: "allow" }, condition: { regexFilter: `^${escapeRegex(url)}$`, resourceTypes: ["main_frame"], tabIds: [tabId] } }] });
  await chrome.alarms.create(`once-${id}`, { delayInMinutes: 1 });
  try { await chrome.tabs.update(tabId, { url }); } catch (error) {
    await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [id] }); throw error;
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "scan-link", title: "Safe UR Link: 링크 검사", contexts: ["link"] });
  chrome.contextMenus.create({ id: "scan-selection", title: "Safe UR Link: 선택한 URL 검사", contexts: ["selection"] });
  queueRebuild().catch(console.error);
});
chrome.runtime.onStartup.addListener(() => queueRebuild().catch(console.error));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && ["blockHosts", "allowHosts", "knownBadUrls"].some(key => key in changes)) queueRebuild().catch(console.error);
});
chrome.contextMenus.onClicked.addListener((info) => {
  const url = urlOf(info.linkUrl || info.selectionText || "");
  if (url) chrome.tabs.create({ url: chrome.runtime.getURL("result.html#" + encodeURIComponent(url)) });
});
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    switch (message.type) {
      case "SCAN_URL": return scanUrl(message.url);
      case "GET_LISTS": return chrome.storage.local.get(STORAGE_DEFAULTS);
      case "EDIT_LIST": return editList(message.kind, message.host, message.add);
      case "PROCEED_ONCE":
        if (sender.url?.split("#")[0] !== chrome.runtime.getURL("warning.html") || !Number.isInteger(sender.tab?.id)) throw new Error("경고 화면에서만 실행할 수 있습니다.");
        await proceedOnce(message.url, sender.tab.id); return { ok: true };
      default: throw new Error("알 수 없는 요청입니다.");
    }
  })().then(value => sendResponse({ ok: true, value }), error => sendResponse({ ok: false, error: error.message }));
  return true;
});
chrome.alarms.onAlarm.addListener(async alarm => {
  if (alarm.name.startsWith("once-")) await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [Number(alarm.name.slice(5))] });
});
chrome.webNavigation.onCommitted.addListener(async details => {
  if (details.frameId !== 0) return;
  const url = urlOf(details.url);
  if (!url) return;
  const rules = await chrome.declarativeNetRequest.getSessionRules();
  const matches = rules.filter(r => r.condition.tabIds?.includes(details.tabId) && r.condition.regexFilter === `^${escapeRegex(url)}$`);
  if (matches.length) await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: matches.map(r => r.id) });
});
