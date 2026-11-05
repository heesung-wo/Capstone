// GitHub Actions와 브라우저에서 공통으로 사용하는 누적 시그니처 규칙.
// 수집 성공: 이번 목록에 있는 URL만 현재 활성 이력(active=true)로 갱신하고,
// 이번 목록에서 빠진 과거 URL은 보관하되 active=false로 전환한다.
// 수집 실패: 해당 소스의 기존 URL/active/마지막 확인 시각을 절대 변경하지 않는다.
import { normalizeUrl } from './common.js';

const isoOr = (date, fallback) => {
  const ms = Date.parse(date);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : fallback;
};

export function mergeHistory(previousRecords, newRecords, succeededSources, observedAt, previousAt = observedAt) {
  const succeeded = new Set(succeededSources);
  const out = new Map();
  const previousTime = isoOr(previousAt, observedAt);
  // 기존 피드가 v0.6.1이면 active / lastObservedAt이 없으므로 이전 피드의 생성 시각을 사용한다.
  for (const row of previousRecords) {
    const url = normalizeUrl(row.url);
    if (!url || typeof row.source !== 'string') continue;
    const old = row.meta || {};
    out.set(`${row.source}|${url}`, {
      url, source: row.source,
      meta: {
        ...old,
        active: succeeded.has(row.source) ? false : old.active !== false,
        lastObservedAt: isoOr(old.lastObservedAt, previousTime)
      }
    });
  }
  for (const row of newRecords) {
    const url = normalizeUrl(row.url);
    if (!url || typeof row.source !== 'string') continue;
    out.set(`${row.source}|${url}`, {
      url, source: row.source,
      meta: { ...(row.meta || {}), active: true, lastObservedAt: observedAt }
    });
  }
  return [...out.values()];
}
