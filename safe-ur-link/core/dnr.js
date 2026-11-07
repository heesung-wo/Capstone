// SafeURLink의 실시간 보호용 DNR 규칙 생성기.
// 실제 네트워크 차단은 service worker가 아니라 브라우저의 DNR 엔진에서 수행한다.
import { normalizeUrl } from './common.js';

// Chrome 121+ : 동적 규칙 전체 30,000개(안전한 block/allow 포함).
// redirect는 이 전체 한도 안에서 별도로 최대 5,000개.
export const MAX_PROTECTION_RULES = 30_000;
// 전체 IndexedDB는 제한 없이 보관하고 실시간 차단 규칙에서만 29,700개를 선별.
// 사용자 지정 차단 도메인은 별도 최대 300개 redirect.
// 허용 규칙까지 포함해 총 30,000개를 초과하면 block 개수를 먼저 줄인다.
export const MAX_SIGNATURE_RULES = 29_700;
// API 수집 상한이 아니라 실시간 보호에만 적용하는 소스별 선정 상한입니다.
// 각 소스 내에서 활성/유효/검증/신뢰도/최신순으로 추리고, 동일 URL은 DNR 규칙 하나로 합칩니다.
export const REALTIME_SOURCE_LIMITS = Object.freeze({
  URLhaus: 9_000, PhishTank: 9_000, PhishingDB: 9_000, ThreatFox: 2_700, Demo: 2
});
export const MAX_BLOCK_HOSTS = 300;
// 마지막 갱신이 너무 오래된 시그니처는 수동 검사 이력에만 남긴다.
export const REALTIME_FRESH_MS = 7 * 24 * 60 * 60_000;
export const DEMO_SIGNATURES = ['https://malware.test/demo', 'https://phishing.test/login'];
const MAIN_FRAME = ['main_frame'];
const escapeRegex = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// URL을 표시할 때 www 접두사는 같은 호스트로 취급하는 기존 설정과 호환.
export function hostMatches(host, entry) {
  return host === entry || host.endsWith('.' + entry);
}

export function validateHostLists(allow, block) {
  const valid = h => typeof h === 'string' && h.length <= 253 &&
    /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(h) &&
    h.split('.').every(label => label.length <= 63 && !label.startsWith('-') && !label.endsWith('-'));
  if (![...allow, ...block].every(valid)) throw new Error('허용/차단 목록에 올바르지 않은 도메인이 있습니다.');
  if (block.length > MAX_BLOCK_HOSTS) throw new Error(`사용자 차단 도메인은 최대 ${MAX_BLOCK_HOSTS}개까지 지원합니다.`);
  if (allow.length + block.length > MAX_PROTECTION_RULES) throw new Error('허용/차단 목록이 실시간 보호 규칙 한도(30,000개)를 초과했습니다.');
}

const rankOf = records => {
  const sources = new Set(records.map(r => r.source)).size;
  const active = records.some(r => r.meta?.online) ? 1 : 0;
  const valid = records.some(r => r.meta?.valid) ? 1 : 0;
  const verified = records.some(r => r.meta?.verified) ? 1 : 0;
  const confidence = Math.max(0, ...records.map(r => r.meta?.confidence || 0));
  const newest = Math.max(0, ...records.map(r => Date.parse(r.meta?.first_seen) || 0));
  const observed = Math.max(0, ...records.map(r => Date.parse(r.meta?.lastObservedAt) || 0));
  return [sources, active, valid, verified, confidence, observed, newest];
};
const byRisk = (a, b) => {
  for (let i = 0; i < a.rank.length; i++) {
    if (a.rank[i] !== b.rank[i]) return b.rank[i] - a.rank[i];
  }
  return a.url.localeCompare(b.url);
};

function canMatchExactly(url) {
  // DNR urlFilter의 메타 문자(*, ^, |)는 문자 그대로 비교할 수 없다.
  // 이 경우 위험한 와일드카드 규칙을 만들어 과잉 차단하는 대신 수동 검사만 허용한다.
  return url.length <= 2000 && !/[\*\^\|]/.test(url) && /^https?:\/\//.test(url);
}

/**
 * @param {Object} settings {realtime, allow, block}
 * @param {Array} records IndexedDB 시그니처 [{url, source, meta}]
 * @param {string} warningBase chrome.runtime.getURL('pages/warning/warning.html')
 * @returns {{rules:Array,stats:Object}}
 */
export function buildProtectionRules(settings, records, warningBase) {
  const allow = [...new Set(settings.allow || [])];
  const block = [...new Set(settings.block || [])];

  const stats = {
    total: 0, signatureRules: 0, userBlockRules: 0, userAllowRules: 0,
    candidateUrls: 0, coveredUrls: 0, skippedUrls: 0,
    excludedByAllow: 0, handledByUserBlock: 0, unsupportedUrls: 0, quotaOverflowUrls: 0,
    historicalUrls: 0, staleUrls: 0,
    selectedBySource: {}, sourceLimits: REALTIME_SOURCE_LIMITS,
    limit: MAX_PROTECTION_RULES
  };
  if (settings.realtime === false) return { rules: [], stats };
  validateHostLists(allow, block);

  const rules = [];
  // 1. 사용자 지정 도메인 전체 차단: 원래 URL을 해시로 보존한다.
  // \\0은 DNR regexSubstitution의 전체 매치이며 JS에서 이스케이프 필요.
  // urlFilter로 일괄 리다이렉트할 때 발생하던 '경고 후 루트 URL만 접속' 오류를 방지한다.
  for (let i = 0; i < block.length; i++) {
    const h = escapeRegex(block[i]);
    rules.push({
      id: 100001 + i,
      priority: 20,
      action: { type: 'redirect', redirect: { regexSubstitution: warningBase + '#\\0' } },
      condition: {
        regexFilter: `^https?://(?:[a-z0-9-]+\\.)*${h}(?::[0-9]+)?(?:[/?#].*)?$`,
        isUrlFilterCaseSensitive: false,
        resourceTypes: MAIN_FRAME
      }
    });
  }

  // 2. 사용자 허용 목록: 실시간 보호 대상 도메인에 예외를 부여한다.
  for (let i = 0; i < allow.length; i++) rules.push({
    id: 200001 + i, priority: 30, action: { type: 'allow' },
    condition: { urlFilter: `||${allow[i]}^`, resourceTypes: MAIN_FRAME }
  });

  // 3. 전체 DB에 저장된 고유 URL을 분류한다.
  // 수동 URL 검사는 이와 무관하게 IndexedDB 전체를 조회한다.
  const grouped = new Map();
  for (const record of records) {
    const u = normalizeUrl(record.url);
    if (!u) continue;
    if (!grouped.has(u)) grouped.set(u, []);
    grouped.get(u).push(record);
  }
  if (grouped.size === 0) {
    for (const url of DEMO_SIGNATURES) grouped.set(url, [{ source: 'Demo', meta: {} }]);
  }
  stats.candidateUrls = grouped.size;

  const candidatesBySource = new Map(Object.keys(REALTIME_SOURCE_LIMITS).map(s => [s, []]));
  const allCandidates = new Map();
  for (const [url, recs] of grouped) {
    // 과거 수집 기록은 차단하지 않는다. 여러 출처에 동일 URL이 있으면 현재 목록에 남아있는 출처만 평가한다.
    const active = recs.filter(r => r.meta?.active !== false);
    if (!active.length) { stats.historicalUrls++; continue; }
    const fresh = active.filter(r => {
      const observed = Date.parse(r.meta?.lastObservedAt);
      return !Number.isFinite(observed) || Date.now() - observed <= REALTIME_FRESH_MS;
    });
    if (!fresh.length) { stats.staleUrls++; continue; }
    const host = new URL(url).hostname;
    if (!canMatchExactly(url)) { stats.unsupportedUrls++; continue; }
    if (allow.some(h => hostMatches(host, h))) { stats.excludedByAllow++; continue; }
    if (block.some(h => hostMatches(host, h))) {
      stats.handledByUserBlock++;
      stats.coveredUrls++;
      continue;
    }
    const row = { url, rank: rankOf(fresh) };
    allCandidates.set(url, row);
    for (const source of new Set(fresh.map(r => r.source))) {
      if (candidatesBySource.has(source)) candidatesBySource.get(source).push(row);
    }
  }

  // 4. '실시간 보호 전용' 각 소스 상한만큼 우선순위 상위 URL을 선정한다.
  // URLhaus 9000 / PhishTank 9000 / PhishingDB 9000 / ThreatFox 2700.
  // 서로 다른 소스에서 나온 동일 URL은 규칙 하나로 합친다.
  const selected = new Map();
  for (const [source, entries] of candidatesBySource) {
    entries.sort(byRisk);
    const selectedRows = entries.slice(0, REALTIME_SOURCE_LIMITS[source]);
    stats.selectedBySource[source] = selectedRows.length;
    for (const row of selectedRows) selected.set(row.url, row);
  }
  const candidates = [...selected.values()].sort(byRisk);
  const available = Math.max(0, Math.min(MAX_SIGNATURE_RULES, MAX_PROTECTION_RULES - rules.length));
  for (const [i, row] of candidates.slice(0, available).entries()) {
    rules.push({
      id: i + 1, priority: 10,
      action: { type: 'block' },
      condition: { urlFilter: `|${row.url}|`, isUrlFilterCaseSensitive: true, resourceTypes: MAIN_FRAME }
    });
  }
  stats.signatureRules = Math.min(candidates.length, available);
  stats.userBlockRules = block.length;
  stats.userAllowRules = allow.length;
  stats.total = rules.length;
  // 전체 DB 중 실시간 보호에 선정되지 못한 URL 수(소스별 제한 + DNR 전체 규칙 제한).
  stats.quotaOverflowUrls = Math.max(0, allCandidates.size - stats.signatureRules);
  stats.skippedUrls = stats.historicalUrls + stats.staleUrls + stats.unsupportedUrls + stats.excludedByAllow + stats.quotaOverflowUrls;
  // 사용자 차단 도메인으로 리다이렉트하는 URL은 skippedUrls에 넣지 않는다.
  return { rules, stats };
}

export function sessionAllowCondition(url, tabId) {
  const target = normalizeUrl(url);
  if (!target || !Number.isInteger(tabId) || tabId < 0) throw new Error('허용할 탭 또는 URL이 올바르지 않습니다.');
  // 정규식은 특수문자가 포함된 URL을 정확하게 다룰 수 있으나 1,000개 한도가 있다.
  // 일반 URL은 DNR urlFilter를 사용해 session regex 규칙을 아낀다.
  return {
    ...(canMatchExactly(target)
      ? { urlFilter: `|${target}|`, isUrlFilterCaseSensitive: true }
      : { regexFilter: '^' + escapeRegex(target) + '$', isUrlFilterCaseSensitive: true }),
    resourceTypes: MAIN_FRAME, tabIds: [tabId]
  };
}
