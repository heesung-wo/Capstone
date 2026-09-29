"use strict";
const raw = location.hash.slice(1);
const target = document.getElementById("target");
const info = document.getElementById("message");
let url;
try { const u = new URL(raw); if (!["http:", "https:"].includes(u.protocol) || u.username || u.password) throw Error(); url = u.href; target.textContent = url; }
catch { info.textContent = "원래 주소를 복원할 수 없습니다."; document.getElementById("proceed").disabled = true; }
document.getElementById("back").addEventListener("click", () => { if (history.length > 1) history.back(); else location.href = "about:blank"; });
document.getElementById("proceed").addEventListener("click", async () => {
  if (!url) return;
  info.textContent = "이동 중…";
  try {
    const result = await chrome.runtime.sendMessage({ type: "PROCEED_ONCE", url });
    if (!result?.ok) throw Error(result?.error || "이동 실패");
  } catch (error) { info.textContent = error.message; }
});
