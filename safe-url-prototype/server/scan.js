"use strict";

// Prefer encrypted transport. The provider's documentation also lists an HTTP endpoint;
// using it requires explicit opt-in when testing on a network where HTTPS is unavailable.
const ENDPOINT = process.env.PHISHTANK_USE_DOCUMENTED_HTTP === "1"
  ? "http://checkurl.phishtank.com/checkurl/"
  : "https://checkurl.phishtank.com/checkurl/";

function normalizeUrl(input) {
  if (typeof input !== "string" || input.length > 4096) throw new Error("URL은 4096자 이하여야 합니다.");
  let url;
  try { url = new URL(input.trim()); } catch { throw new Error("올바른 URL을 입력하세요."); }
  if (!["http:", "https:"].includes(url.protocol) || !url.hostname || url.username || url.password) {
    throw new Error("사용자 정보가 없는 http/https URL만 검사할 수 있습니다.");
  }
  url.hash = ""; // Fragment is never sent in an HTTP request.
  return url.href;
}

function bool(value) {
  return value === true || value === 1 || (typeof value === "string" && ["true", "yes", "y", "1"].includes(value.toLowerCase()));
}

function analyzePhishTank(data) {
  const raw = data?.results?.url0 ?? data?.results;
  if (!raw || typeof raw !== "object" || !Object.hasOwn(raw, "in_database")) throw new Error("PhishTank 응답 형식이 예상과 다릅니다.");
  const inDatabase = bool(raw.in_database);
  const verified = inDatabase && bool(raw.verified);
  const valid = verified && bool(raw.valid);
  const score = !inDatabase || (verified && !valid) ? 0 : 10 + (verified && valid ? 30 : 0);
  const reasons = [];
  if (inDatabase) reasons.push("PhishTank 등록 (+10)");
  if (verified && valid) reasons.push("검증된 피싱 URL (+30)");
  if (verified && !valid) reasons.push("검증 결과 유효한 피싱 URL이 아님 (PhishTank 점수 0)");
  if (!inDatabase) reasons.push("PhishTank에서 발견되지 않음 (안전하다는 뜻은 아님)");
  return { available: true, score, malicious: verified && valid, inDatabase, verified, valid,
    detailPage: typeof raw.phish_detail_page === "string" ? raw.phish_detail_page : null, reasons };
}

function analyzeUrl(input) {
  const u = new URL(input);
  const reasons = [];
  let score = 0;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(u.hostname) || u.hostname.startsWith("[")) { score += 3; reasons.push("IP 주소 사용 (+3)"); }
  if (u.hostname.split(".").some(label => label.startsWith("xn--"))) { score += 3; reasons.push("Punycode 도메인 (+3)"); }
  if (input.length > 120) { score += 2; reasons.push("긴 URL (+2)"); }
  if (input.includes("@")) { score += 2; reasons.push("@ 문자 포함 (+2)"); }
  return { score, reasons };
}

async function checkPhishTank(url, fetchImpl = fetch) {
  const body = new URLSearchParams({ url, format: "json" });
  const response = await fetchImpl(ENDPOINT, { method: "POST", redirect: "error", signal: AbortSignal.timeout(8000),
    headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "SafeURLink-Capstone-Prototype/0.2 (local educational test)" },
    body: body.toString() });
  if (!response.ok) throw new Error(`PhishTank HTTP ${response.status}`);
  return analyzePhishTank(await response.json());
}

async function scan(input, fetchImpl = fetch) {
  const url = normalizeUrl(input);
  const heuristic = analyzeUrl(url);
  let phishTank;
  try { phishTank = await checkPhishTank(url, fetchImpl); }
  catch (error) { phishTank = { available: false, score: 0, malicious: false, reasons: ["PhishTank 조회 실패: " + error.message] }; }
  const totalScore = phishTank.score + heuristic.score;
  const status = phishTank.malicious ? "MALICIOUS" : totalScore >= 20 ? "SUSPICIOUS" : phishTank.available ? "UNKNOWN" : "UNVERIFIED";
  return { url, status, totalScore, maximumCurrentScore: 50, futureMaximumScore: 100,
    sources: { urlhaus: { available: false, score: 0, reasons: ["Auth-Key 필요: 이 버전에서 조회하지 않음"] }, phishTank, heuristic } };
}

module.exports = { normalizeUrl, analyzePhishTank, analyzeUrl, scan };
