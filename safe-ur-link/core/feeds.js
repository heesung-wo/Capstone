// 위협 인텔리전스 수집기. 각 함수는 [{url, meta}]를 반환한다.
// 실제 악성 URL에 접속하지 않고, 정보 제공자의 공식 피드만 다운로드한다.
// 반환되는 URL은 정규화 전 원본이다. 정규화/저장은 background/background.js에서 처리한다.

export const REFRESH_MS = Object.freeze({
  URLhaus: 60 * 60_000,       // 공식 최소 5분보다 여유 있게 1시간
  PhishTank: 60 * 60_000,     // 인증된 경우: 원본 데이터가 1시간마다 갱신
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

export async function phishtank({ phishKey = '', userAgent = '' } = {}) {
  const key = phishKey.trim();
  const endpoint = key
    ? `https://data.phishtank.com/data/${encodeURIComponent(key)}/online-valid.json`
    : 'https://data.phishtank.com/data/online-valid.json';
  // PhishTank는 식별 가능한 User-Agent를 요구한다. 서버(Node/Actions)에서 실행할 때만 지정할 수 있다.
  const response = await getResponse(endpoint, userAgent ? { headers: { 'User-Agent': userAgent } } : {});
  const text = await response.text();
  assertNotHtml(text, 'PhishTank');
  let data;
  try { data = JSON.parse(text); } catch { throw new Error('PhishTank: 유효한 JSON이 아닙니다.'); }
  if (!Array.isArray(data)) throw new Error('PhishTank: JSON 배열이 아닙니다.');
  const records = data.filter(e => e && validHttpURL(e.url)).map(e => ({
    url: e.url,
    meta: {
      verified: e.verified === 'yes' || e.verified === true,
      online: e.online === 'yes' || e.online === true,
      threat: 'phishing',
      target: e.target || undefined,
      first_seen: dateISO(e.submission_time),
      verified_at: dateISO(e.verification_time)
    }
  }));
  if (!records.length) throw new Error('PhishTank: 유효한 URL이 없는 JSON입니다.');
  return records;
}

// Phishing.Database (MIT 라이선스). 공식 데이터 파일은 phish.co.za 에서 제공한다.
// 프로젝트가 직접 HTTP 상태를 점검해 분류한 "ACTIVE(또는 아직 활성일 수 있는)" 링크 목록이다.
export const PHISHING_DB_URL = 'https://phish.co.za/latest/phishing-links-ACTIVE.txt';
export async function phishingDatabase({ userAgent = '' } = {}) {
  const response = await getResponse(PHISHING_DB_URL, userAgent ? { headers: { 'User-Agent': userAgent } } : {});
  const text = await response.text();
  assertNotHtml(text, 'PhishingDB');
  // 한 줄에 URL 하나. 이 파일은 같은 링크가 중복으로 들어간 적이 있어서 이후 단계(normalizeRows)에서 중복을 제거한다.
  const records = text.split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#') && validHttpURL(s))
    .map(url => ({ url, meta: { threat: 'phishing' } }));
  // 이 목록은 등록 시각과 검증 여부를 제공하지 않으므로 first_seen/verified/online을 임의로 만들지 않는다.
  // ("ACTIVE"는 프로젝트의 점검 결과일 뿐, 지금 이 순간 접속 가능하다는 보장이 아니므로 online=true로 표시하지 않는다.)
  if (!records.length) throw new Error('PhishingDB: 유효한 URL이 없는 파일입니다.');
  return records;
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
