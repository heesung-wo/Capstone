// URL 정규화 + 휴리스틱 평가 + 점수/판정 (Popup, Service Worker 공용)
export function normalizeUrl(raw) {
  let s = String(raw || '').trim();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'http://' + s;
  try {
    const u = new URL(s);
    if (!['http:', 'https:'].includes(u.protocol)) return null;
    u.hash = '';               // fragment 제거, 호스트 소문자화·기본 포트 제거는 URL 객체가 처리
    return u.href;
  } catch { return null; }
}

export function hostOf(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return ''; }
}

// 공통 수동 검사와 실시간 보호의 7일 이력 기준을 동일하게 관리합니다.
export const REALTIME_FRESH_MS = 7 * 24 * 60 * 60_000;

const KEYWORDS = ['login', 'signin', 'verify', 'account', 'password', 'secure', 'update', 'banking', 'confirm', 'wallet'];

export function heuristics(raw) {
  const reasons = [];
  let score = 0;
  const add = (pts, text) => { score += pts; reasons.push({ points: pts, text }); };
  const s = String(raw || '');
  let u;
  try { u = new URL(normalizeUrl(s) || ''); } catch { return { score: 0, reasons }; }
  const host = u.hostname;
  const authority = s.replace(/^[a-z]+:\/\//i, '').split(/[/?#]/)[0];

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) add(8, 'IP 주소를 직접 사용하는 주소입니다');
  if (host.split('.').some(l => l.startsWith('xn--'))) add(8, 'Punycode(국제화) 도메인을 사용합니다');
  if (authority.includes('@')) add(6, "'@' 문자로 실제 접속 호스트를 혼동시키는 구조입니다");
  if (host.split('.').length >= 5) add(5, '서브도메인이 과도하게 많습니다');
  const kw = KEYWORDS.filter(k => (u.pathname + u.search + host).toLowerCase().includes(k));
  if (kw.length) add(5, `의심 키워드가 포함되어 있습니다 (${kw.slice(0, 4).join(', ')})`);
  if (u.href.length > 100) add(4, `URL이 지나치게 깁니다 (${u.href.length}자)`);
  const enc = (s.match(/%[0-9a-f]{2}/gi) || []).length;
  const special = (s.match(/[-_=&;+~]/g) || []).length;
  if (enc >= 5 || special >= 15) add(2, '과도한 URL 인코딩 또는 특수문자가 사용되었습니다');
  if (u.protocol === 'http:') add(2, 'HTTPS를 사용하지 않습니다');
  return { score: Math.min(score, 40), reasons };
}

// records: [{source, meta:{verified, online, confidence, threat, first_seen}}]
export function externalScore(records) {
  const reasons = [];
  if (!records.length) return { score: 0, reasons };
  const sources = [...new Set(records.map(r => r.source))];
  let score = 30;
  reasons.push({ points: 30, text: `${sources[0]}에서 동일 URL이 악성으로 확인되었습니다` });
  if (sources.length >= 2) { score += 10; reasons.push({ points: 10, text: `두 번째 데이터 소스(${sources[1]})에서도 교차 탐지되었습니다` }); }
  const extra = Math.min(Math.max(sources.length - 2, 0) * 5, 10);
  if (extra) { score += extra; reasons.push({ points: extra, text: `추가 데이터 소스 ${sources.length - 2}곳에서 교차 탐지되었습니다` }); }

  let meta = 0; const notes = [];
  const m = records.map(r => r.meta || {});
  if (m.some(x => x.verified)) { meta += 3; notes.push('검증됨'); }
  if (m.some(x => x.online)) { meta += 3; notes.push('활성 상태'); }
  if (m.some(x => (x.confidence ?? 0) >= 75)) { meta += 2; notes.push('높은 신뢰도'); }
  const seen = Math.max(0, ...m.map(x => Date.parse(x.first_seen) || 0));
  if (seen && Date.now() - seen < 30 * 864e5) { meta += 2; notes.push('최근 30일 내 등록'); }
  if (meta) { score += meta; reasons.push({ points: meta, text: `메타데이터 근거: ${notes.join(', ')}` }); }
  return { score: Math.min(score, 60), reasons };
}

export function verdictOf(externalHit, total) {
  if (externalHit) return 'Malicious';
  return total >= 30 ? 'Suspicious' : 'No Threat Detected';
}
