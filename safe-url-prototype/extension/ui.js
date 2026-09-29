"use strict";
const $ = id => document.getElementById(id);
async function message(type, extras = {}) {
  const response = await chrome.runtime.sendMessage({ type, ...extras });
  if (!response?.ok) throw new Error(response?.error || "확장 프로그램 오류");
  return response.value;
}
function element(tag, text, className) {
  const e = document.createElement(tag);
  e.textContent = text;
  if (className) e.className = className;
  return e;
}
function renderResult(data) {
  const root = $("result"); root.hidden = false; root.replaceChildren();
  root.append(element("h2", `판정: ${data.status}`, data.status));
  root.append(element("p", `검사 URL: ${data.url}`, "url"));
  root.append(element("p", `근거 점수: ${data.totalScore} / ${data.maximumCurrentScore} (URLhaus 제외)`));
  for (const [label, source] of [["PhishTank", data.sources.phishTank], ["URL 특징", data.sources.heuristic], ["URLhaus", data.sources.urlhaus]]) {
    root.append(element("h2", `${label}: ${source.score}${label === "PhishTank" ? " / 40" : label === "URL 특징" ? " / 10" : " / 50"}`));
    const list = document.createElement("ul");
    for (const reason of source.reasons.length ? source.reasons : ["특이사항 없음"]) list.append(element("li", reason));
    root.append(list);
  }
  if (data.sources.phishTank.malicious) root.append(element("p", "검증된 피싱 URL은 점수와 관계없이 악성으로 판정합니다."));
  if (data.status === "UNKNOWN" || data.status === "UNVERIFIED") root.append(element("p", "악성 정보가 없거나 조회에 실패했으며 안전을 보증하지 않습니다.", "muted"));
}
async function runScan(url) {
  $("message").textContent = "조회 중…";
  $("result").hidden = true;
  try { renderResult(await message("SCAN_URL", { url })); $("message").textContent = "검사 완료"; }
  catch (error) { $("message").textContent = `검사 실패: ${error.message} (node server/server.js 실행 여부 확인)`; }
}
async function showLists() {
  const state = await message("GET_LISTS");
  for (const [kind, id] of [["blockHosts", "blocks"], ["allowHosts", "allows"]]) {
    const list = $(id); list.replaceChildren();
    for (const host of state[kind]) {
      const row = element("li", host, "list-row");
      const button = element("button", "삭제", "secondary");
      button.addEventListener("click", async () => {
        try { await message("EDIT_LIST", { kind, host, add: false }); await showLists(); }
        catch (error) { $("message").textContent = error.message; }
      });
      row.append(button); list.append(row);
    }
  }
}
if ($("scanForm")) {
  $("scanForm").addEventListener("submit", e => { e.preventDefault(); runScan($("url").value); });
  $("current").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) { $("url").value = tab.url; runScan(tab.url); }
  });
  for (const [button, kind] of [["block", "blockHosts"], ["allow", "allowHosts"]]) {
    $(button).addEventListener("click", async () => {
      try { await message("EDIT_LIST", { kind, host: $("host").value, add: true }); $("host").value = ""; await showLists(); $("message").textContent = "목록에 추가했습니다."; }
      catch (error) { $("message").textContent = error.message; }
    });
  }
  showLists().catch(error => $("message").textContent = error.message);
} else {
  let url;
  try { url = decodeURIComponent(location.hash.slice(1)); } catch { url = ""; }
  if (url) runScan(url); else $("message").textContent = "검사할 URL이 없습니다.";
}
