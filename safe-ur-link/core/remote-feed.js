import { normalizeUrl } from './common.js';

export const SCHEMA_VERSION = 1;
export const SOURCES = ['URLhaus', 'PhishTank', 'PhishingDB', 'ThreatFox', 'Demo'];
const SOURCE_SET = new Set(SOURCES);

export function validateFeed(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data) || data.schema !== SCHEMA_VERSION) {
    throw new Error('시그니처 형식이 다릅니다 (schema: 1 필요)');
  }
  const ms = Date.parse(data.generatedAt);
  if (!Number.isFinite(ms) || ms > Date.now() + 3600_000) {
    throw new Error('배포된 데이터의 생성 시각이 올바르지 않습니다.');
  }
  if (!Array.isArray(data.signatures)) {
    throw new Error('시그니처 목록이 올바르지 않습니다.');
  }
  if (!data.signatures.length && data.emptyDataset !== true) {
    throw new Error('빈 시그니처 데이터입니다. 이전 데이터베이스를 유지합니다.');
  }
  const seen = new Set();
  const records = [];
  for (const row of data.signatures) {
    if (!row || typeof row.url !== 'string' || typeof row.source !== 'string' || !SOURCE_SET.has(row.source)) {
      throw new Error('지원하지 않는 시그니처 레코드가 있습니다.');
    }
    const url = normalizeUrl(row.url);
    if (!url || !/^https?:\/\//i.test(row.url)) throw new Error('시그니처 URL이 올바르지 않습니다.');
    if (row.source === 'Demo' && !new URL(url).hostname.endsWith('.test')) {
      throw new Error('시연용 시그니처는 .test 주소만 허용합니다.');
    }
    const id = `${row.source}|${url}`;
    if (seen.has(id)) continue;
    seen.add(id);
    const m = row.meta && typeof row.meta === 'object' && !Array.isArray(row.meta) ? row.meta : {};
    // 기존 점수 계산에 필요한 비민감 필드만 보관. 외부에서 임의의 객체를 통째로 저장하지 않는다.
    const meta = {
      online: m.online === true,
      verified: m.verified === true,
      valid: m.valid === true,
      confidence: Number.isFinite(m.confidence) ? Math.max(0, Math.min(100, m.confidence)) : 0,
      threat: typeof m.threat === 'string' ? m.threat.slice(0, 100) : '',
      first_seen: typeof m.first_seen === 'string' ? m.first_seen : undefined,
      active: m.active !== false,
      lastObservedAt: typeof m.lastObservedAt === 'string' && Number.isFinite(Date.parse(m.lastObservedAt))
        ? new Date(m.lastObservedAt).toISOString() : undefined
    };
    records.push({ url, source: row.source, meta });
  }
  if (!records.length && data.emptyDataset !== true) throw new Error('유효한 시그니처가 없습니다.');
  const sources = data.sourceStatus && typeof data.sourceStatus === 'object' && !Array.isArray(data.sourceStatus)
    ? Object.fromEntries(Object.entries(data.sourceStatus)
      .filter(([key, val]) => SOURCE_SET.has(key) && val && ['updated', 'retained', 'unavailable'].includes(val.state))
      .map(([key, val]) => [key, { state: val.state, lastSuccessAt: typeof val.lastSuccessAt === 'string' ? val.lastSuccessAt : undefined }]))
    : {};
  return { generatedAt: new Date(ms).toISOString(), records, demoOnly: records.every(r => r.source === 'Demo'), sourceStatus: sources };
}

export async function downloadFeed(url, fetchFn = fetch) {
  if (!/^https:\/\//i.test(url) || /YOUR_NAME|YOUR_REPO/i.test(url)) {
    throw new Error('개발자가 core/config.js에 GitHub Pages 주소를 설정해야 합니다.');
  }
  let res;
  try {
    res = await fetchFn(url, { cache: 'no-store', credentials: 'omit' });
  } catch (e) { throw new Error(`시그니처 서버 연결 실패: ${e.message || e}`); }
  if (!res.ok) throw new Error(`시그니처 서버 HTTP ${res.status}`);
  // html 오류 문서, 인증 페이지 등을 거부한다.
  const body = await res.text();
  if (/^\s*<!doctype\s+html|^\s*<html\b/i.test(body)) throw new Error('시그니처 대신 HTML 페이지가 반환되었습니다. Pages 배포 설정을 확인하세요.');
  let data;
  try { data = JSON.parse(body); } catch { throw new Error('시그니처 서버 응답이 JSON이 아닙니다.'); }
  return validateFeed(data);
}
