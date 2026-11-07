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

// PhishTank 공식 다운로드 피드는 JSON/CSV 형태가 존재한다.
// 인증 경로에서 404를 받으면 파일 형식을 바꿔 보고, 마지막으로 공식 공개 피드를 확인한다.
// 401/403/429/509 및 서버 장애는 우회하지 않고 상위 빌드 재시도/보존 정책에 맡긴다.
export async function phishtank({ phishKey = '', userAgent = '', onFallback = () => {} } = {}) {
  const key = phishKey.trim();
  const base = 'https://data.phishtank.com/data/';
  const prefix = key ? `${base}${encodeURIComponent(key)}/` : base;
  const candidates = [
    { url: `${prefix}online-valid.json`, type: 'json', label: '인증 JSON' },
    { url: `${prefix}online-valid.csv`, type: 'csv', label: '인증 CSV' }
  ];
  if (key) {
    candidates.push(
      { url: `${base}online-valid.json`, type: 'json', label: '공개 JSON' },
      { url: `${base}online-valid.csv`, type: 'csv', label: '공개 CSV' }
    );
  }
  const opts = userAgent ? { headers: { 'User-Agent': userAgent } } : {};
  for (let i = 0; i < candidates.length; i++) {
    const candidate = candidates[i];
    let response;
    try {
      response = await getResponse(candidate.url, opts);
    } catch (error) {
      if (error.httpStatus !== 404) throw error;
      // URL에 인증키가 포함되어 있으므로 상세 URL을 로그로 기록하지 않는다.
      if (i < candidates.length - 1) onFallback(`PhishTank: ${candidate.label} HTTP 404 → 다른 공식 다운로드 형식으로 재시도`);
      continue;
    }
    const body = await response.text();
    assertNotHtml(body, 'PhishTank');
    let entries;
    if (candidate.type === 'json') {
      try { entries = JSON.parse(body); }
      catch { throw new Error('PhishTank: 유효한 JSON이 아닙니다.'); }
      if (!Array.isArray(entries)) throw new Error('PhishTank: JSON 배열이 아닙니다.');
    } else {
      const rows = body.split(/\r?\n/).filter(line => line && !line.startsWith('#'));
      const fields = rows[0] ? csvLine(rows[0].replace(/^\uFEFF/, '')).map(x => x.trim().toLowerCase()) : [];
      if (!fields.includes('url') || !fields.includes('verified') || !fields.includes('online')) {
        throw new Error('PhishTank: CSV 헤더 형식이 올바르지 않습니다.');
      }
      entries = [];
      for (const line of rows.slice(1)) {
        const cols = csvLine(line);
        const item = {};
        for (const field of ['url', 'verified', 'online', 'target', 'submission_time', 'verification_time']) {
          const index = fields.indexOf(field);
          item[field] = index < 0 ? '' : cols[index] || '';
        }
        entries.push(item);
      }
    }
    const records = entries.filter(e => e && validHttpURL(e.url)).map(e => ({
      url: e.url,
      meta: {
        verified: e.verified === 'yes' || e.verified === true,
        valid: true, // 공식 online-valid 피드: 커뮤니티가 검증한 유효 URL
        online: e.online === 'yes' || e.online === true,
        threat: 'phishing',
        target: e.target || undefined,
        first_seen: dateISO(e.submission_time),
        verified_at: dateISO(e.verification_time)
      }
    }));
    if (!records.length) throw new Error('PhishTank: 유효한 URL이 없는 데이터입니다.');
    if (i > 0) onFallback(`PhishTank: ${candidate.label} 경로에서 ${records.length}건 확보`);
    return records;
  }
  throw new Error('PhishTank: 공식 JSON/CSV 다운로드 경로가 모두 HTTP 404입니다. PHISHTANK_KEY와 파일 다운로드 권한을 확인하세요.');
}

// Phishing.Database (MIT 라이선스). 공식 데이터 파일은 phish.co.za 에서 제공한다.
// 프로젝트가 직접 HTTP 상태를 점검해 분류한 "ACTIVE(또는 아직 활성일 수 있는)" 링크 목록이다.
export const PHISHING_DB_URL = 'https://phish.co.za/latest/phishing-links-ACTIVE.txt';
export const PHISHING_DB_FALLBACK_URL = 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt';
// 공식 서버의 일시 오류/연결 실패/데이터 형식 오류에만 미러를 사용한다.
// 403·429 등 접근 금지/호출 제한은 우회하지 않는다.
export async function phishingDatabase({ userAgent = '', onFallback = () => {} } = {}) {
  const opts = userAgent ? { headers: { 'User-Agent': userAgent } } : {};
  const parse = text => {
    assertNotHtml(text, 'PhishingDB');
    const records = text.split(/\r?\n/).map(s => s.trim())
      .filter(s => s && !s.startsWith('#') && validHttpURL(s))
      .map(url => ({ url, meta: { threat: 'phishing' } }));
    // ACTIVE 데이터에는 등록시각이나 커뮤니티 검증 여부 정보가 없다.
    if (!records.length) throw new Error('PhishingDB: 유효한 URL이 없는 파일입니다.');
    return records;
  };
  const fetchAndParse = async url => parse(await (await getResponse(url, opts)).text());
  try { return await fetchAndParse(PHISHING_DB_URL); }
  catch (error) {
    const allowed = error.httpStatus == null || [404, 408, 500, 502, 503, 504].includes(error.httpStatus);
    if (!allowed) throw error;
    onFallback(`PhishingDB: 공식 배포 서버 실패 (${error.httpStatus ? `HTTP ${error.httpStatus}` : '연결 또는 데이터 오류'}) → GitHub 원본 시도`);
    try { return await fetchAndParse(PHISHING_DB_FALLBACK_URL); }
    catch (fallbackError) {
      const combined = new Error(`PhishingDB: 공식 서버 실패 (${error.message || error}), GitHub 대체 주소도 실패 (${fallbackError.message || fallbackError})`);
      combined.httpStatus = fallbackError.httpStatus || error.httpStatus;
      throw combined;
    }
  }
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
