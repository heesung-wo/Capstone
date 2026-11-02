// 위협 인텔리전스 수집기. 각 함수는 [{url, meta}]를 반환한다.
// 실제 악성 URL에 접속하지 않고, 정보 제공자의 공식 피드만 다운로드한다.
// 반환되는 URL은 정규화 전 원본이다. 정규화/저장은 background/background.js에서 처리한다.

export const REFRESH_MS = Object.freeze({
  URLhaus: 60 * 60_000,       // 공식 최소 5분보다 여유 있게 1시간
  PhishTank: 24 * 60 * 60_000, // 비인증 공개 피드는 하루 한 번만 수집
  PhishingDB: 6 * 60 * 60_000,
  ThreatFox: 6 * 60 * 60_000
});
export const PHISHTANK_ANONYMOUS_MS = 24 * 60 * 60_000; // 보수적인 자체 정책, 공식 보장량 아님

function needKey(source) {
  const error = new Error(`${source}: 무료 abuse.ch Auth-Key가 필요합니다 (https://auth.abuse.ch/)`);
  error.code = 'AUTH_REQUIRED';
  throw error;
}

async function getResponse(url, options = {}) {
  let response;
  try {
    response = await fetch(url, { cache: 'no-store', credentials: 'omit', ...options });
  } catch (err) {
    throw new Error(`네트워크 요청 실패 (CORS, 접속 또는 연결 상태 확인): ${err.message || err}`);
  }
  if (!response.ok) {
    const error = new Error(`HTTP ${response.status}${response.status === 509 || response.status === 429 ? ' (호출 제한)' : ''}`);
    error.httpStatus = response.status;
    error.retryAfter = response.headers.get('Retry-After');
    throw error;
  }
  return response;
}

function assertNotHtml(text, source) {
  if (/^\s*(?:<!doctype\s+html|<html\b)/i.test(text)) {
    throw new Error(`${source}: 데이터 대신 HTML 응답이 도착했습니다 (인증, 차단 페이지 또는 보안 검사)`);
  }
}

function csvLine(line) {
  const cols = [];
  let value = '', quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (quoted && line[i + 1] === '"') { value += '"'; i++; }
      else quoted = !quoted;
    } else if (ch === ',' && !quoted) { cols.push(value); value = ''; }
    else value += ch;
  }
  cols.push(value);
  return cols;
}

function dateISO(value) {
  const s = String(value || '').trim();
  if (!s || /^(?:none|null)$/i.test(s)) return undefined;
  const adjusted = s.replace(/ UTC$/i, 'Z').replace(/^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)/, '$1T$2')
    .replace(/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)$/, '$1Z');
  const ms = Date.parse(adjusted);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : undefined;
}

function validHttpURL(url) {
  try { return ['http:', 'https:'].includes(new URL(url).protocol); }
  catch { return false; }
}

export async function urlhaus({ authKey = '' } = {}) {
  if (!authKey.trim()) needKey('URLhaus');
  // 2026년 공식 공개 문서의 인증된 CSV Export 경로. 헤더가 아닌 URL 경로에 키가 들어간다.
  const endpoint = `https://urlhaus-api.abuse.ch/v2/files/exports/${encodeURIComponent(authKey.trim())}/recent.csv`;
  const response = await getResponse(endpoint);
  const text = await response.text();
  assertNotHtml(text, 'URLhaus');

  const lines = text.split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#'));
  // CSV 필드: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
  const header = lines[0] ? csvLine(lines[0]).map(x => x.toLowerCase().trim()) : [];
  const hasHeader = header.includes('url');
  const at = (cols, field, fallback) => cols[hasHeader ? header.indexOf(field) : fallback];
  const records = [];
  for (const line of lines.slice(hasHeader ? 1 : 0)) {
    const cols = csvLine(line);
    const url = (at(cols, 'url', 2) || '').trim();
    if (!validHttpURL(url)) continue;
    const status = (at(cols, 'url_status', 3) || '').toLowerCase().trim();
    records.push({
      url,
      meta: {
        online: status === 'online',
        threat: at(cols, 'threat', 5) || 'malware_download',
        first_seen: dateISO(at(cols, 'dateadded', 1)),
        last_online: dateISO(at(cols, 'last_online', 4)),
        tags: (at(cols, 'tags', 6) || '').split(',').map(s => s.trim()).filter(Boolean)
      }
    });
  }
  if (!records.length) throw new Error('URLhaus: 유효한 URL이 없는 CSV입니다. 데이터 형식을 확인하세요.');
  return records;
}

// PhishTank: 키 없이 이용 가능한 공식 공개 피드 다운로드.
// 공식 정책은 "하루 몇 차례" (정확한 횟수 비공개). Actions는 하루 1회 실행하고,
// 같은 UTC 날짜에 재실행할 경우 scripts/build-feed.mjs의 파일 캐시를 재사용한다.
// 압축 CSV를 우선 사용한다. 404일 때만 압축 JSON으로 한 번 대체하여 불필요한 호출을 피한다.
// 429/509(호출 제한), 403 등의 응답에서 자동 재시도를 하지 않는다.
export const PHISHTANK_PUBLIC_CSV_GZ = 'https://data.phishtank.com/data/online-valid.csv.gz';
export const PHISHTANK_PUBLIC_JSON_GZ = 'https://data.phishtank.com/data/online-valid.json.gz';

async function readGzipOrPlain(response) {
  // fetch가 Content-Encoding을 자동 해제한 경우도 고려한다.
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    return await new Response(stream).text();
  }
  return new TextDecoder('utf-8').decode(bytes);
}

function isYes(value) {
  return value === true || /^(yes|true|y|1)$/i.test(String(value ?? '').trim());
}

function parsePhishTankCSV(text) {
  assertNotHtml(text, 'PhishTank');
  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/).filter(s => s.trim());
  const header = csvLine(lines.shift() || '').map(s => s.toLowerCase().trim());
  const urlIdx = header.indexOf('url');
  const verifiedIdx = header.indexOf('verified');
  const onlineIdx = header.indexOf('online');
  if (urlIdx < 0 || verifiedIdx < 0 || onlineIdx < 0) {
    throw new Error('PhishTank: CSV 필수 열(url, verified, online)을 찾지 못했습니다.');
  }
  const idx = key => header.indexOf(key);
  const read = (cols, key) => {
    const i = idx(key);
    return i < 0 ? '' : (cols[i] || '').trim();
  };
  const records = [];
  for (const line of lines) {
    const cols = csvLine(line);
    const url = (cols[urlIdx] || '').trim();
    // 다운로드 피드는 공식적으로 검증 완료 및 온라인 URL만 포함한다.
    if (!validHttpURL(url) || !isYes(cols[verifiedIdx]) || !isYes(cols[onlineIdx])) continue;
    records.push({
      url,
      meta: {
        verified: true,
        online: true,
        threat: 'phishing',
        target: read(cols, 'target') || undefined,
        first_seen: dateISO(read(cols, 'submission_time')),
        verified_at: dateISO(read(cols, 'verification_time'))
      }
    });
  }
  if (!records.length) throw new Error('PhishTank: 유효한 검증·활성 피싱 URL이 없는 CSV입니다.');
  return records;
}

function parsePhishTankJSON(text) {
  assertNotHtml(text, 'PhishTank');
  let data;
  try { data = JSON.parse(text); } catch { throw new Error('PhishTank: 유효한 JSON이 아닙니다.'); }
  if (!Array.isArray(data)) throw new Error('PhishTank: JSON 배열이 아닙니다.');
  const records = data.filter(e => e && validHttpURL(e.url) && isYes(e.verified) && isYes(e.online))
    .map(e => ({
      url: e.url,
      meta: {
        verified: true,
        online: true,
        threat: 'phishing',
        target: e.target || undefined,
        first_seen: dateISO(e.submission_time),
        verified_at: dateISO(e.verification_time)
      }
    }));
  if (!records.length) throw new Error('PhishTank: 유효한 검증·활성 피싱 URL이 없는 JSON입니다.');
  return records;
}

export async function phishtank({ userAgent = '' } = {}) {
  // 익명 피드는 HTTP header의 User-Agent가 필수적으로 중요하다.
  const headers = { 'User-Agent': userAgent || 'phishtank/safe-ur-link-capstone' };
  let response;
  try {
    response = await getResponse(PHISHTANK_PUBLIC_CSV_GZ, {
      headers, signal: AbortSignal.timeout(90_000)
    });
  } catch (error) {
    if (error?.httpStatus !== 404) throw new Error(`PhishTank: 공개 CSV 피드 요청 실패 — ${error?.message || error}`);
    console.warn('PhishTank: 공개 CSV가 HTTP 404를 반환하여 공식 공개 JSON gzip을 한 번 시도합니다.');
    response = await getResponse(PHISHTANK_PUBLIC_JSON_GZ, {
      headers, signal: AbortSignal.timeout(90_000)
    });
    return parsePhishTankJSON(await readGzipOrPlain(response));
  }
  return parsePhishTankCSV(await readGzipOrPlain(response));
}

// Phishing.Database (MIT 라이선스). 기본 피드에 장애/차단이 생기면 같은 프로젝트의 GitHub 원본 파일로 대체한다.
// 주의: GitHub 원본 파일은 수십 MB 이상이므로 일 단위 배치 수집 환경에서만 사용한다.
export const PHISHING_DB_URL = 'https://phish.co.za/latest/phishing-links-ACTIVE.txt';
export const PHISHING_DB_FALLBACK_URL = 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt';

function parsePhishingDB(text) {
  assertNotHtml(text, 'PhishingDB');
  // URL 1개/줄. 주석, 빈 줄, http/https 이외의 행은 제외한다.
  const records = text.split(/\r?\n/).map(s => s.trim())
    .filter(s => s && !s.startsWith('#') && validHttpURL(s))
    .map(url => ({ url, meta: { threat: 'phishing' } }));
  if (!records.length) throw new Error('PhishingDB: 유효한 URL이 없는 파일입니다.');
  // ACTIVE는 공급자의 점검 결과이며 지금 당장 온라인이라는 보장이 아니다.
  return records;
}

export async function phishingDatabase({ userAgent = '' } = {}) {
  const headers = userAgent ? { 'User-Agent': userAgent } : undefined;
  const endpoints = [
    { label: '공식 피드', url: PHISHING_DB_URL, timeoutMs: 45_000 },
    { label: 'GitHub 원본', url: PHISHING_DB_FALLBACK_URL, timeoutMs: 120_000 }
  ];
  const errors = [];
  for (const { label, url, timeoutMs } of endpoints) {
    try {
      const response = await getResponse(url, { ...(headers ? { headers } : {}), signal: AbortSignal.timeout(timeoutMs) });
      const records = parsePhishingDB(await response.text());
      if (errors.length) console.warn(`PhishingDB: 대체 수집 경로(${label})에서 ${records.length.toLocaleString()}건을 확보했습니다.`);
      return records;
    } catch (error) {
      errors.push(`${label}: ${error?.message || error}`);
      console.warn(`PhishingDB: ${label} 다운로드 실패 (${error?.message || error})`);
    }
  }
  throw new Error(`PhishingDB: 기본 및 대체 피드 모두 실패 — ${errors.join(' / ')}`);
}

export async function threatfox({ authKey = '' } = {}) {
  if (!authKey.trim()) needKey('ThreatFox');
  const response = await getResponse('https://threatfox-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Auth-Key': authKey.trim() },
    body: JSON.stringify({ query: 'get_iocs', days: 7 })
  });
  const json = await response.json().catch(() => { throw new Error('ThreatFox: 유효한 JSON이 아닙니다.'); });
  if (json.query_status !== 'ok' && json.query_status !== 'no_result') {
    throw new Error(`ThreatFox: API 상태 ${String(json.query_status || 'unknown')}`);
  }
  return (Array.isArray(json.data) ? json.data : []).filter(e => e.ioc_type === 'url' && validHttpURL(e.ioc))
    .map(e => ({
      url: e.ioc,
      meta: {
        verified: false, // 제보된 IOC를 임의로 검증 완료로 표시하지 않음
        confidence: Number(e.confidence_level) || 0,
        threat: e.threat_type,
        malware: e.malware_printable,
        first_seen: dateISO(e.first_seen_utc || e.first_seen)
      }
    }));
}

export const FEEDS = { URLhaus: urlhaus, PhishTank: phishtank, PhishingDB: phishingDatabase, ThreatFox: threatfox };
