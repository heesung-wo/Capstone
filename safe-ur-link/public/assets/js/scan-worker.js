// 웹에서는 전체 signatures.json을 한꺼번에 파싱하지 않는다.
// 작은 web-index.json으로 즉시 준비 상태를 표시한 뒤, 검사할 URL의 샤드만 다운로드한다.
// 배포 원본 signatures.json과 같은 레코드를 사용하며 URL에 직접 접속하지 않는다.
import { validateFeed } from '../../core/remote-feed.js';
import { evaluateUrl } from '../../core/scan.js';
import { normalizeUrl } from '../../core/common.js';
import { shardForUrl } from '../../core/web-shards.js';

let manifest = null;
let loading = false;
const shardCache = new Map(); // 최근 조회한 샤드만 보관
const inFlight = new Map();
const MAX_CACHED_SHARDS = 12;

function validateManifest(data) {
  if (data?.schema !== 1 || data.format !== 'safeurlink-shards-v1' ||
    !Number.isFinite(Date.parse(data.generatedAt)) ||
    !Number.isInteger(data.shardCount) || data.shardCount < 1 || data.shardCount > 4096 ||
    (data.shardCount & (data.shardCount - 1)) !== 0 ||
    !Number.isInteger(data.signatureCount) || data.signatureCount < 0 ||
    !Number.isInteger(data.uniqueCount) || data.uniqueCount < 0 ||
    !data.sourceCounts || typeof data.sourceCounts !== 'object') {
    throw new Error('웹 검사 인덱스 형식이 올바르지 않습니다. GitHub Actions를 다시 배포해 주세요.');
  }
  return data;
}

async function getJSON(url, label) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  try {
    const res = await fetch(url, { cache: 'no-store', credentials: 'omit', signal: controller.signal });
    if (!res.ok) throw new Error(`${label} HTTP ${res.status}`);
    const data = await res.json();
    return data;
  } catch (e) {
    if (e?.name === 'AbortError') throw new Error(`${label} 응답 시간 초과 (20초)`);
    throw e;
  } finally {
    clearTimeout(timeout);
  }
}

async function refresh() {
  if (loading) return;
  loading = true;
  self.postMessage({ type: 'loading', hasPrevious: Boolean(manifest) });
  try {
    const url = new URL('../../web-index.json', import.meta.url);
    url.searchParams.set('t', String(Date.now()));
    const next = validateManifest(await getJSON(url, '인덱스 다운로드 실패'));
    if (manifest?.generatedAt !== next.generatedAt) {
      shardCache.clear();
      inFlight.clear();
    }
    manifest = next;
    self.postMessage({
      type: 'ready', generatedAt: next.generatedAt, demoOnly: next.demoOnly,
      count: next.signatureCount, uniqueCount: next.uniqueCount,
      sources: next.sourceCounts
    });
  } catch (e) {
    self.postMessage({ type: 'load-error', error: String(e?.message || e), hasPrevious: Boolean(manifest) });
  } finally {
    loading = false;
  }
}

async function recordsForUrl(url, version) {
  const shard = shardForUrl(url, version.shardCount);
  const key = `${version.generatedAt}:${shard}`;
  let records = shardCache.get(key);
  if (!records) {
    if (!inFlight.has(key)) {
      const task = (async () => {
        const u = new URL(`../../web-shards/${shard}.json`, import.meta.url);
        u.searchParams.set('v', version.generatedAt);
        const json = await getJSON(u, '시그니처 샤드 다운로드 실패');
        if (json?.schema !== 1 || json.shard !== shard || json.generatedAt !== version.generatedAt || !Array.isArray(json.signatures)) {
          throw new Error('시그니처와 웹 인덱스의 버전이 일치하지 않습니다. GitHub Pages 배포를 확인해 주세요.');
        }
        // 원본 확장 프로그램과 동일한 형식 검증기를 샤드 단위로 적용한다.
        const feed = validateFeed({ schema: 1, generatedAt: version.generatedAt, signatures: json.signatures, emptyDataset: true });
        const map = new Map();
        for (const row of feed.records) {
          if (!map.has(row.url)) map.set(row.url, []);
          map.get(row.url).push(row);
        }
        shardCache.set(key, map);
        if (shardCache.size > MAX_CACHED_SHARDS) shardCache.delete(shardCache.keys().next().value);
        return map;
      })().finally(() => inFlight.delete(key));
      inFlight.set(key, task);
    }
    records = await inFlight.get(key);
  } else {
    // LRU: 최근 사용한 샤드는 마지막으로 이동
    shardCache.delete(key);
    shardCache.set(key, records);
  }
  return records.get(url) || [];
}

async function check(id, raw) {
  if (!manifest) {
    self.postMessage({ type: 'check-result', id, error: '시그니처 인덱스가 아직 준비되지 않았습니다.' });
    return;
  }
  try {
    const normalized = normalizeUrl(raw);
    if (!normalized) {
      self.postMessage({ type: 'check-result', id, result: evaluateUrl(raw, []) });
      return;
    }
    const version = manifest;
    const records = await recordsForUrl(normalized, version);
    self.postMessage({ type: 'check-result', id, result: evaluateUrl(raw, records) });
  } catch (e) {
    self.postMessage({ type: 'check-result', id, error: String(e?.message || e) });
  }
}

self.onmessage = event => {
  const { type, url, id } = event.data || {};
  if (type === 'refresh') void refresh();
  if (type === 'check') void check(id, url);
};

void refresh();
