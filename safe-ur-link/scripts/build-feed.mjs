// GitHub Actions에서 실행되는 시그니처 수집 스크립트.
// 비밀 키는 환경변수로만 읽고, 결과물(public/signatures.json)에는 URL과 최소 메타데이터만 담는다.
//   ABUSE_CH_AUTH_KEY  : URLhaus / ThreatFox
//   PHISHTANK_KEY      : PhishTank (선택)
//   PHISHTANK_USER_AGENT : PhishTank 요청에 쓸 식별 가능한 User-Agent
//   PUBLISH_* / REDISTRIBUTION_CONFIRMED / OPENPHISH_WRITTEN_PERMISSION : 공개 재배포 허용 스위치
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeUrl } from '../core/common.js';
import { urlhaus, phishtank, openphish, threatfox } from '../core/feeds.js';
import { validateFeed, SCHEMA_VERSION } from '../core/remote-feed.js';

const MAX_RECORDS = 300_000; // core/remote-feed.js 의 확장 프로그램 허용 한도와 동일

// 재배포가 확인된 소스만 공개 JSON에 포함한다. 기본값은 모두 비공개(false).
export function enabledSources(env = {}) {
  const confirmed = env.REDISTRIBUTION_CONFIRMED === 'true';
  const on = name => confirmed && env[`PUBLISH_${name}`] === 'true';
  return {
    URLhaus: on('URLHAUS'),
    ThreatFox: on('THREATFOX'),
    PhishTank: on('PHISHTANK'),
    OpenPhish: on('OPENPHISH') && env.OPENPHISH_WRITTEN_PERMISSION === 'true'
  };
}

export function defaultCollectors(env = {}) {
  return {
    URLhaus: () => urlhaus({ authKey: env.ABUSE_CH_AUTH_KEY || '' }),
    ThreatFox: () => threatfox({ authKey: env.ABUSE_CH_AUTH_KEY || '' }),
    PhishTank: () => phishtank({
      phishKey: env.PHISHTANK_KEY || '',
      userAgent: env.PHISHTANK_USER_AGENT || 'safe-ur-link-feed-builder'
    }),
    OpenPhish: () => openphish()
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

function demoSignatures(now) {
  const first_seen = new Date(now).toISOString();
  return ['https://malware.test/demo', 'https://phishing.test/login'].map(url => ({
    url, source: 'Demo',
    meta: { online: true, verified: true, confidence: 90, threat: 'demo', first_seen }
  }));
}

export async function buildFeed(env = {}, { collectors = defaultCollectors(env), now = Date.now(), log = () => {} } = {}) {
  const enabled = enabledSources(env);
  const names = Object.keys(enabled).filter(n => enabled[n]);
  const secrets = [env.ABUSE_CH_AUTH_KEY, env.PHISHTANK_KEY].filter(Boolean);
  const redact = msg => secrets.reduce((s, k) => s.split(k).join('***'), String(msg));

  let signatures = [];
  const failures = [];
  if (!names.length) {
    log('공개가 허용된 소스가 없어 시연용(.test) 데이터만 생성합니다.');
    signatures = demoSignatures(now);
  } else {
    const seen = new Set();
    for (const name of names) {
      try {
        let count = 0;
        for (const item of await collectors[name]()) {
          const url = normalizeUrl(item.url);
          if (!url || seen.has(`${name}|${url}`)) continue;
          seen.add(`${name}|${url}`);
          signatures.push({ url, source: name, meta: slimMeta(item.meta) });
          count++;
        }
        log(`${name}: ${count}건`);
      } catch (e) {
        failures.push(`${name}: ${redact(e?.message || e)}`);
      }
    }
    // 일부라도 실패하면 배포하지 않는다 → Pages에는 마지막 정상 배포본이 그대로 남는다.
    if (failures.length) throw new Error(`피드 수집 실패, 이전 배포본을 유지합니다.\n${failures.join('\n')}`);
  }
  if (signatures.length > MAX_RECORDS) throw new Error(`시그니처가 ${MAX_RECORDS.toLocaleString()}건을 초과했습니다 (${signatures.length}건).`);

  const feed = {
    schema: SCHEMA_VERSION,
    generatedAt: new Date(now).toISOString(),
    signatures,
    ...(signatures.length ? {} : { emptyDataset: true })
  };
  validateFeed(feed); // 확장 프로그램이 거부할 형식이면 여기서 빌드를 실패시킨다.
  return feed;
}

async function main() {
  const feed = await buildFeed(process.env, { log: m => console.log(m) });
  const dir = fileURLToPath(new URL('../public/', import.meta.url));
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, 'signatures.json'), JSON.stringify(feed));
  await writeFile(path.join(dir, 'index.html'),
    '<!doctype html><meta charset="utf-8"><title>Safe UR Link signatures</title><p>signatures.json 만 제공하는 공개 피드입니다.</p>');
  console.log(`완료: ${feed.signatures.length}건 → public/signatures.json`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(e => { console.error(e.message || e); process.exit(1); });
}
