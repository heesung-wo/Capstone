// GitHub Actions에서 실행되는 시그니처 수집 스크립트.
// 비밀 키는 환경변수로만 읽고, 결과물(public/signatures.json)에는 URL과 최소 메타데이터만 담는다.
//   ABUSE_CH_AUTH_KEY  : URLhaus / ThreatFox
//   PhishTank         : API 키 없이 일 1회 공개 CSV.gz 다운로드 (actions/cache 권장)
//   PHISHTANK_USER_AGENT : PhishTank 요청에 쓸 식별 가능한 User-Agent
//   PUBLISH_* / REDISTRIBUTION_CONFIRMED : 소스별 공개 재배포 허용 스위치 (URLHAUS, THREATFOX, PHISHTANK, PHISHING_DB)
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeUrl } from '../core/common.js';
import { urlhaus, phishtank, phishingDatabase, threatfox } from '../core/feeds.js';
import { validateFeed, SCHEMA_VERSION } from '../core/remote-feed.js';

const MAX_RECORDS = 300_000; // core/remote-feed.js 의 확장 프로그램 허용 한도와 동일 (안전장치)
// 소스별 공개 건수 상한. 파일 크기와 확장 프로그램의 저장/검사 부담을 줄이기 위한 값이다.
// 필요하면 워크플로 환경변수 MAX_PER_SOURCE 로 바꿀 수 있다.
export const MAX_PER_SOURCE = 10_000;

// 일시적인 오류(5xx, 429, 네트워크 실패)만 재시도한다. 401/403/404 같은 설정 오류는 재시도해도 소용없으므로 바로 실패시킨다.
const RETRY_DELAYS_MS = [5_000, 20_000];
const isTransient = e => e?.httpStatus >= 500 || e?.httpStatus === 429 || /네트워크 요청 실패/.test(e?.message || '');

// 재배포가 확인된 소스만 공개 JSON에 포함한다. 기본값은 모두 비공개(false).
export function enabledSources(env = {}) {
  const confirmed = env.REDISTRIBUTION_CONFIRMED === 'true';
  const on = name => confirmed && env[`PUBLISH_${name}`] === 'true';
  return {
    URLhaus: on('URLHAUS'),
    ThreatFox: on('THREATFOX'),
    PhishTank: on('PHISHTANK'),
    PhishingDB: on('PHISHING_DB')
  };
}

// MIT 라이선스 등 고지가 필요한 소스. 공개 피드(signatures.json, index.html)에 그대로 실린다.
export const NOTICES = {
  PhishingDB: {
    name: 'Phishing.Database',
    license: 'MIT License',
    copyright: 'Copyright (c) 2018-2025 Nissar Chababy (@funilrys); Copyright (c) 2018-2025 Phishing.Database Contributors',
    url: 'https://github.com/Phishing-Database/Phishing.Database'
  }
};

// GitHub Actions의 actions/cache로 같은 UTC 날짜의 PhishTank 수집 결과를 재사용한다.
// 최초 성공 실행에서 .cache/phishtank-daily.json을 생성한 후 일별 키로 보관한다.
const PHISHTANK_DAILY_CACHE = fileURLToPath(new URL('../.cache/phishtank-daily.json', import.meta.url));

export async function readPhishtankDailyCache(day, cacheFile = PHISHTANK_DAILY_CACHE) {
  try {
    const cached = JSON.parse(await readFile(cacheFile, 'utf8'));
    if (cached?.utcDay !== day || !Array.isArray(cached.records) || !cached.records.length) return null;
    return cached.records;
  } catch { return null; }
}

export async function writePhishtankDailyCache(day, records, cacheFile = PHISHTANK_DAILY_CACHE) {
  await mkdir(path.dirname(cacheFile), { recursive: true });
  await writeFile(cacheFile, JSON.stringify({ utcDay: day, records }));
}

export function defaultCollectors(env = {}) {
  return {
    URLhaus: () => urlhaus({ authKey: env.ABUSE_CH_AUTH_KEY || '' }),
    ThreatFox: () => threatfox({ authKey: env.ABUSE_CH_AUTH_KEY || '' }),
    PhishTank: async () => {
      const day = new Date().toISOString().slice(0, 10);
      const cached = await readPhishtankDailyCache(day);
      if (cached) {
        console.log(`PhishTank: UTC ${day} 캐시 재사용 — 외부 다운로드 생략 (${cached.length.toLocaleString()}건)`);
        return cached;
      }
      const records = await phishtank({
        userAgent: env.PHISHTANK_USER_AGENT || 'phishtank/safe-ur-link-capstone (+https://github.com/heesung-wo/Capstone)'
      });
      await writePhishtankDailyCache(day, records);
      return records;
    },
    PhishingDB: () => phishingDatabase({ userAgent: env.FEED_USER_AGENT || 'safe-ur-link-feed-builder (+https://github.com/heesung-wo/Capstone)' })
  };
}

// 확장 프로그램의 점수 계산에 필요한 비민감 필드만 남긴다.
function slimMeta(m = {}) {
  const meta = {
    online: m.online === true,
    verified: m.verified === true,
    confidence: Number.isFinite(m.confidence) ? m.confidence : 0,
    threat: typeof m.threat === 'string' ? m.threat.slice(0, 100) : ''
  };
  if (typeof m.first_seen === 'string') meta.first_seen = m.first_seen;
  return meta;
}

// 한 소스의 원본 행을 정규화·중복 제거하고 비민감 메타만 남긴다.
export function normalizeRows(source, rows) {
  const seen = new Set();
  const out = [];
  for (const row of rows || []) {
    const url = normalizeUrl(row?.url);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push({ url, source, meta: slimMeta(row.meta || {}) });
  }
  return out;
}

// 상한을 넘으면 위험 신호가 강한 행부터 남긴다: 활성(online) → 검증됨 → 신뢰도 높음 → 최근 등록.
// 점수가 같은 행(예: 등록 시각이 없는 목록)은 원본 파일의 순서에 기대지 않도록 "날짜 시드 기반 무작위 표본"으로 고른다.
// 같은 날, 같은 입력이면 항상 같은 결과가 나오고(재실행해도 안정적), 날짜가 바뀌면 표본이 바뀐다.
export function pickTop(rows, limit = MAX_PER_SOURCE, seed = '') {
  if (rows.length <= limit) return rows;
  const tie = url => createHash('sha1').update(`${seed}|${url}`).digest().readUInt32BE(0);
  const key = r => [r.meta.online ? 1 : 0, r.meta.verified ? 1 : 0, r.meta.confidence || 0, Date.parse(r.meta.first_seen) || 0];
  return rows.map(r => ({ r, k: key(r), t: tie(r.url) }))
    .sort((a, b) => b.k[0] - a.k[0] || b.k[1] - a.k[1] || b.k[2] - a.k[2] || b.k[3] - a.k[3] || a.t - b.t)
    .slice(0, limit).map(x => x.r);
}

function demoSignatures(now) {
  const first_seen = new Date(now).toISOString();
  return ['https://malware.test/demo', 'https://phishing.test/login'].map(url => ({
    url, source: 'Demo',
    meta: { online: true, verified: true, confidence: 90, threat: 'demo', first_seen }
  }));
}

export async function buildFeed(env = {}, { collectors = defaultCollectors(env), now = Date.now(), log = () => {}, sleep = ms => new Promise(r => setTimeout(r, ms)) } = {}) {
  const limit = Number(env.MAX_PER_SOURCE) > 0 ? Math.floor(Number(env.MAX_PER_SOURCE)) : MAX_PER_SOURCE;
  const seed = new Date(now).toISOString().slice(0, 10);   // 표본 선택용 날짜 시드 (UTC)
  const enabled = enabledSources(env);
  const names = Object.keys(enabled).filter(n => enabled[n]);
  const secrets = [env.ABUSE_CH_AUTH_KEY].filter(Boolean);
  const redact = msg => secrets.reduce((s, k) => s.split(k).join('***'), String(msg));
  // OPTIONAL_SOURCES(쉼표로 구분)에 적은 소스는 수집에 실패해도 나머지 소스만으로 배포한다.
  // 단, 실패한 소스의 데이터는 그날 피드에서 빠지므로 확장 프로그램에서도 해당 소스 데이터가 비워진다.
  const optional = new Set(String(env.OPTIONAL_SOURCES || '').split(',').map(x => x.trim()).filter(Boolean));
  const withRetry = async (name, fn) => {
    for (let i = 0; ; i++) {
      try { return await fn(); }
      catch (e) {
        if (i >= RETRY_DELAYS_MS.length || !isTransient(e)) throw e;
        log(`${name}: 일시적 오류(${redact(e.message || e)}) — ${RETRY_DELAYS_MS[i] / 1000}초 후 재시도 (${i + 1}/${RETRY_DELAYS_MS.length})`);
        await sleep(RETRY_DELAYS_MS[i]);
      }
    }
  };

  let signatures = [];
  const counts = {};
  const failures = [];
  const warnings = [];
  const unavailableSources = [];
  const succeeded = [];
  if (!names.length) {
    log('공개가 허용된 소스가 없어 시연용(.test) 데이터만 생성합니다.');
    signatures = demoSignatures(now);
  } else {
    for (const name of names) {
      try {
        let rows = normalizeRows(name, await withRetry(name, () => collectors[name]()));
        const found = rows.length;
        rows = pickTop(rows, limit, seed);
        if (found > rows.length) log(`${name}: 원본 ${found.toLocaleString()}건 중 상위 ${rows.length.toLocaleString()}건만 사용 (소스별 상한)`);
        // 주의: push(...rows)는 12만 건 이상에서 "Maximum call stack size exceeded"가 발생하므로 반복문을 쓴다.
        for (const r of rows) signatures.push(r);
        counts[name] = rows.length;
        succeeded.push(name);
        log(`${name}: ${rows.length}건`);
      } catch (e) {
        const msg = `${name}: ${redact(e?.message || e)}`;
        if (optional.has(name)) { warnings.push(msg); unavailableSources.push(name); log(`경고: ${msg} — 선택 소스이므로 이번 배포에서는 제외합니다.`); }
        else failures.push(msg);
      }
    }
    // 일부라도 실패하면 배포하지 않는다 → Pages에는 마지막 정상 배포본이 그대로 남는다.
    if (failures.length) throw new Error(`피드 수집 실패, 이전 배포본을 유지합니다.\n${failures.join('\n')}`);
    // 선택 소스까지 전부 실패했다면 빈 피드로 기존 데이터를 지우지 않도록 중단한다.
    if (!succeeded.length) throw new Error(`수집에 성공한 소스가 없어 이전 배포본을 유지합니다.\n${warnings.join('\n')}`);
  }
  if (signatures.length > MAX_RECORDS) {
    const detail = Object.entries(counts).map(([k, n]) => `${k} ${n}건`).join(', ');
    throw new Error(`시그니처가 허용 한도 ${MAX_RECORDS.toLocaleString()}건을 초과했습니다 (총 ${signatures.length}건: ${detail}). `
      + 'MAX_PER_SOURCE를 줄이거나 공개 소스를 줄이세요.');
  }

  const feed = {
    schema: SCHEMA_VERSION,
    generatedAt: new Date(now).toISOString(),
    signatures,
    // 수집 실패한 선택 소스의 이름만 기록해 확장 프로그램이 기존 마지막 정상 데이터를 지우지 않게 한다.
    ...(unavailableSources.length ? { unavailableSources } : {}),
    ...(succeeded.some(n => NOTICES[n]) ? { notices: succeeded.filter(n => NOTICES[n]).map(n => ({ source: n, ...NOTICES[n] })) } : {}),
    ...(signatures.length ? {} : { emptyDataset: true })
  };
  validateFeed(feed); // 확장 프로그램이 거부할 형식이면 여기서 빌드를 실패시킨다.
  return feed;
}

async function main() {
  const feed = await buildFeed(process.env, { log: m => console.log(m) });
  const dir = fileURLToPath(new URL('../public/', import.meta.url));
  await mkdir(dir, { recursive: true });
  const esc = t => String(t).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const notices = (feed.notices || []).map(n =>
    `<li><a href="${esc(n.url)}">${esc(n.name)}</a> — ${esc(n.license)}. ${esc(n.copyright)}</li>`).join('');
  await writeFile(path.join(dir, 'index.html'),
    '<!doctype html><meta charset="utf-8"><title>Safe UR Link signatures</title>'
    + '<p>signatures.json 만 제공하는 공개 피드입니다.</p>'
    + (notices ? `<h2>Third-party data notices</h2><ul>${notices}</ul>` : ''));
  const json = JSON.stringify(feed);
  await writeFile(path.join(dir, 'signatures.json'), json);
  console.log(`완료: ${feed.signatures.length.toLocaleString()}건, ${(Buffer.byteLength(json) / 1048576).toFixed(1)}MB → public/signatures.json`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(e => { console.error(e.message || e); process.exit(1); });
}
