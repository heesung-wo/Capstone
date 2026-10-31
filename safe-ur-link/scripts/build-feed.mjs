// GitHub Actions 전용 수집기. 외부 API 키는 환경변수에서만 읽고 게시 데이터에 절대 넣지 않는다.
import { writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { urlhaus, threatfox, phishtank, openphish } from './collectors.mjs';
import { normalizeUrl } from '../core/common.js';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const enabled = {
  URLhaus: process.env.PUBLISH_URLHAUS === 'true',
  ThreatFox: process.env.PUBLISH_THREATFOX === 'true',
  PhishTank: process.env.PUBLISH_PHISHTANK === 'true',
  OpenPhish: process.env.PUBLISH_OPENPHISH === 'true'
};
const selected = Object.keys(enabled).filter(k => enabled[k]);
const providers = {
  URLhaus: () => urlhaus({ authKey: process.env.ABUSE_CH_AUTH_KEY || '' }),
  ThreatFox: () => threatfox({ authKey: process.env.ABUSE_CH_AUTH_KEY || '' }),
  PhishTank: () => phishtank({ phishKey: process.env.PHISHTANK_KEY || '', userAgent: process.env.PHISHTANK_USER_AGENT || '' }),
  OpenPhish: () => openphish()
};

function sanitizeMeta(m = {}) {
  return {
    verified: m.verified === true,
    online: m.online === true,
    confidence: Number.isFinite(m.confidence) ? Math.max(0, Math.min(100, m.confidence)) : 0,
    threat: String(m.threat || '').slice(0, 100),
    ...(m.first_seen && !Number.isNaN(Date.parse(m.first_seen)) ? { first_seen: m.first_seen } : {})
  };
}
export function normalizeRows(source, rows) {
  if (!Array.isArray(rows)) throw new Error(`${source}: API 응답이 목록이 아닙니다.`);
  const map = new Map();
  for (const row of rows) {
    if (typeof row?.url !== 'string' || !/^https?:\/\//i.test(row.url)) continue;
    const url = normalizeUrl(row.url);
    if (url && !map.has(url)) map.set(url, { url, source, meta: sanitizeMeta(row.meta) });
  }
  return [...map.values()];
}
async function main() {
  if (selected.length && process.env.REDISTRIBUTION_CONFIRMED !== 'true') {
    throw new Error('외부 데이터를 공개 재배포하려면 먼저 제공자 허가/약관을 검토하고 REDISTRIBUTION_CONFIRMED=true로 설정하세요.');
  }
  if (enabled.OpenPhish && process.env.OPENPHISH_WRITTEN_PERMISSION !== 'true') {
    throw new Error('OpenPhish: 서면 재배포 허가 확인 없이는 공개 배포를 활성화할 수 없습니다.');
  }
  if ((enabled.URLhaus || enabled.ThreatFox) && !process.env.ABUSE_CH_AUTH_KEY) {
    throw new Error('ABUSE_CH_AUTH_KEY GitHub Actions Secret이 없습니다.');
  }
  let signatures = [], sources = [];
  if (!selected.length) {
    // 기본 배포는 .test 시연 데이터만 사용. 실존하는 악성 주소는 공개하지 않는다.
    signatures = normalizeRows('Demo', [
      { url: 'http://malware.test/demo', meta: { threat: 'demo' } },
      { url: 'https://phishing.test/login', meta: { threat: 'demo' } }
    ]);
    sources = [{ name: 'Demo', count: signatures.length }];
  } else {
    for (const name of selected) {
      // 한 소스라도 수집 실패하면 배포를 취소한다. 이전 GitHub Pages 배포는 유지됨.
      const list = normalizeRows(name, await providers[name]());
      if (!list.length && name !== 'ThreatFox') throw new Error(`${name}: 유효한 URL이 0건이므로 배포를 중단합니다.`);
      signatures.push(...list);
      sources.push({ name, count: list.length });
      console.log(`${name}: ${list.length}개 수집됨`);
    }
  }
  if (!signatures.length) throw new Error('통합 시그니처가 0건입니다. 배포 중단.');
  if (signatures.length > 300_000) throw new Error('시그니처 300,000건 초과, 분할 파일 설계 필요');
  const feed = { schema: 1, generatedAt: new Date().toISOString(), sources, signatures };
  await mkdir(join(ROOT, 'public'), { recursive: true });
  await writeFile(join(ROOT, 'public', 'signatures.json'), JSON.stringify(feed), 'utf8');
  console.log(`GitHub Pages 공개 JSON 생성 완료: ${signatures.length}건`);
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch(error => {
    // 오류 본문에 키가 포함된 경우를 대비해 마스킹한다.
    let msg = String(error?.message || error);
    for (const key of [process.env.ABUSE_CH_AUTH_KEY, process.env.PHISHTANK_KEY].filter(Boolean)) msg = msg.replaceAll(key, '[SECRET]');
    console.error(msg);
    process.exitCode = 1;
  });
}
