// GitHub Actions에서 실행되는 시그니처 수집 스크립트.
// 비밀 키는 환경변수로만 읽고, 결과물(public/signatures.json)에는 URL과 최소 메타데이터만 담는다.
//   ABUSE_CH_AUTH_KEY  : URLhaus / ThreatFox
//   PHISHTANK_KEY      : PhishTank (선택)
//   PHISHTANK_USER_AGENT : PhishTank 요청에 쓸 식별 가능한 User-Agent
//   PUBLISH_* / REDISTRIBUTION_CONFIRMED : 소스별 공개 재배포 허용 스위치 (URLHAUS, THREATFOX, PHISHTANK, PHISHING_DB)
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeUrl } from '../core/common.js';
import { urlhaus, phishtank, phishingDatabase, threatfox } from '../core/feeds.js';
import { validateFeed, SCHEMA_VERSION } from '../core/remote-feed.js';

// 수집 단계에서는 소스별 고정 건수 제한을 적용하지 않습니다.
// 해당 소스의 현재 피드가 제공한 HTTP(S) URL을 정규화/중복 제거하여 모두 배포합니다.
// 실시간 보호에 적용할 소스별 건수와 선별 우선순위는 core/dnr.js에서만 관리합니다.

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

export function defaultCollectors(env = {}) {
  return {
    URLhaus: () => urlhaus({ authKey: env.ABUSE_CH_AUTH_KEY || '' }),
    ThreatFox: () => threatfox({ authKey: env.ABUSE_CH_AUTH_KEY || '' }),
    PhishTank: () => phishtank({
      phishKey: '',
      userAgent: env.PHISHTANK_USER_AGENT || 'SafeURLinkFeedBuilder'
    }),
    PhishingDB: () => phishingDatabase({ userAgent: env.FEED_USER_AGENT || 'SafeURLinkFeedBuilder (+https://github.com/heesung-wo/Capstone)' })
  };
}

// 확장 프로그램의 점수 계산에 필요한 비민감 필드만 남긴다.
function slimMeta(m = {}) {
  const meta = {
    online: m.online === true,
    verified: m.verified === true,
    valid: m.valid === true,
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

function demoSignatures(now) {
  const first_seen = new Date(now).toISOString();
  return ['https://malware.test/demo', 'https://phishing.test/login'].map(url => ({
    url, source: 'Demo',
    meta: { online: true, verified: true, confidence: 90, threat: 'demo', first_seen }
  }));
}

export async function buildFeed(env = {}, { collectors = defaultCollectors(env), now = Date.now(), log = () => {}, sleep = ms => new Promise(r => setTimeout(r, ms)) } = {}) {
  const enabled = enabledSources(env);
  const names = Object.keys(enabled).filter(n => enabled[n]);
  const secrets = [env.ABUSE_CH_AUTH_KEY, env.PHISHTANK_KEY].filter(Boolean);
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
  const succeeded = [];
  if (!names.length) {
    log('공개가 허용된 소스가 없어 시연용(.test) 데이터만 생성합니다.');
    signatures = demoSignatures(now);
  } else {
    for (const name of names) {
      try {
        let rows = normalizeRows(name, await withRetry(name, () => collectors[name]()));
        // 수동 URL 검사는 이 전체 시그니처를 이용하므로 수집 단계에서 자르지 않습니다.
        // 주의: push(...rows)는 12만 건 이상에서 "Maximum call stack size exceeded"가 발생하므로 반복문을 쓴다.
        for (const r of rows) signatures.push(r);
        counts[name] = rows.length;
        succeeded.push(name);
        log(`${name}: ${rows.length}건`);
      } catch (e) {
        const msg = `${name}: ${redact(e?.message || e)}`;
        if (optional.has(name)) { warnings.push(msg); log(`경고: ${msg} — 선택 소스이므로 이번 배포에서는 제외합니다.`); }
        else failures.push(msg);
      }
    }
    // 일부라도 실패하면 배포하지 않는다 → Pages에는 마지막 정상 배포본이 그대로 남는다.
    if (failures.length) throw new Error(`피드 수집 실패, 이전 배포본을 유지합니다.\n${failures.join('\n')}`);
    // 선택 소스까지 전부 실패했다면 빈 피드로 기존 데이터를 지우지 않도록 중단한다.
    if (!succeeded.length) throw new Error(`수집에 성공한 소스가 없어 이전 배포본을 유지합니다.\n${warnings.join('\n')}`);
  }
  const feed = {
    schema: SCHEMA_VERSION,
    generatedAt: new Date(now).toISOString(),
    signatures,
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
    '<!doctype html><meta charset="utf-8"><title>SafeURLink signatures</title>'
    + '<p>signatures.json 만 제공하는 공개 피드입니다.</p>'
    + (notices ? `<h2>Third-party data notices</h2><ul>${notices}</ul>` : ''));
  const json = JSON.stringify(feed);
  await writeFile(path.join(dir, 'signatures.json'), json);
  console.log(`완료: ${feed.signatures.length.toLocaleString()}건, ${(Buffer.byteLength(json) / 1048576).toFixed(1)}MB → public/signatures.json`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(e => { console.error(e.message || e); process.exit(1); });
}
