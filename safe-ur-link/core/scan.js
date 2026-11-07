// 확장 프로그램과 웹사이트가 공유하는 순수 URL 판정 엔진.
// 시그니처 레코드를 전달받아 동일한 판정·점수·이력 정책을 적용한다.
// 외부 URL로 네트워크 요청을 전송하지 않는다.
import { normalizeUrl, hostOf, heuristics, externalScore, verdictOf, REALTIME_FRESH_MS } from './common.js';

const matchesHost = (host, entry) => host === entry || host.endsWith('.' + entry);

export function evaluateUrl(raw, records = [], settings = {}) {
  const url = normalizeUrl(raw);
  if (!url) return { error: 'http/https URL만 검사할 수 있습니다.' };
  const host = hostOf(url);
  const base = { url, host, checkedAt: Date.now() };
  if ((settings.allow || []).some(entry => matchesHost(host, entry))) {
    return { ...base, verdict: 'No Threat Detected', score: 0, userList: 'allow', sources: [],
      reasons: [{ points: 0, text: '사용자 허용 목록에 등록된 도메인입니다' }] };
  }
  if ((settings.block || []).some(entry => matchesHost(host, entry))) {
    return { ...base, verdict: 'Malicious', score: 100, userList: 'block', sources: [],
      reasons: [{ points: 0, text: '사용자 차단 목록에 등록된 도메인입니다' }] };
  }

  const historyOnly = records.length > 0 && records.every(r => {
    if (r.meta?.active === false) return true;
    const seen = Date.parse(r.meta?.lastObservedAt);
    return Number.isFinite(seen) && Date.now() - seen > REALTIME_FRESH_MS;
  });
  const ext = externalScore(records), heur = heuristics(raw);
  const score = Math.min(ext.score + heur.score, 100);
  return {
    ...base, verdict: historyOnly ? 'Suspicious' : verdictOf(records.length > 0, score), score, historyOnly,
    externalScore: ext.score, heuristicScore: heur.score,
    lastObservedAt: records.map(r => Date.parse(r.meta?.lastObservedAt) || 0).reduce((a,b) => Math.max(a,b), 0) || null,
    sources: [...new Set(records.map(r => r.source))],
    threats: [...new Set(records.map(r => r.meta?.threat).filter(Boolean))],
    reasons: [...(historyOnly ? [{ points: 0, text: '과거 악성 등록 이력이 있지만 최신 피드에 없거나 7일 이상 재확인되지 않았습니다. 현재 악성 여부는 미확정입니다.', kind: 'history' }] : []),
      ...ext.reasons.map(r => ({ ...r, kind: 'external' })), ...heur.reasons.map(r => ({ ...r, kind: 'heuristic' }))]
  };
}
