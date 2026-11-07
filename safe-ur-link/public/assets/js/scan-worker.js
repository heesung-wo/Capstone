// 대용량 공개 시그니처를 UI 스레드와 분리해 읽는다.
// URL을 실제 열지 않고, 동일 출처의 signatures.json만 fetch한다.
import { validateFeed } from '../../core/remote-feed.js';
import { evaluateUrl } from '../../core/scan.js';
import { normalizeUrl } from '../../core/common.js';

let index = new Map();
let loaded = false;
let loading = false;

async function refresh() {
  if (loading) return;
  loading = true;
  self.postMessage({ type: 'loading', hasPrevious: loaded });
  try {
    const res = await fetch(new URL('../../signatures.json', import.meta.url), {
      cache: 'no-store', credentials: 'omit'
    });
    if (!res.ok) throw new Error(`시그니처 다운로드 실패 (HTTP ${res.status})`);
    const data = await res.json();
    const feed = validateFeed(data); // 확장 프로그램이 쓰는 동일한 검증 모듈
    const next = new Map();
    const counts = {};
    for (const record of feed.records) {
      if (!next.has(record.url)) next.set(record.url, []);
      next.get(record.url).push(record);
      counts[record.source] = (counts[record.source] || 0) + 1;
    }
    // 유효한 피드 구성을 완전히 마친 다음에만 현재 인덱스를 교체한다.
    index = next;
    loaded = true;
    self.postMessage({
      type: 'ready', generatedAt: feed.generatedAt, demoOnly: feed.demoOnly,
      count: feed.records.length, uniqueCount: next.size,
      sources: counts
    });
  } catch (e) {
    // 새 피드 오류로 기존에 정상 로드된 데이터까지 버리지 않는다.
    self.postMessage({ type: 'load-error', error: String(e?.message || e), hasPrevious: loaded });
  } finally {
    loading = false;
  }
}

self.onmessage = event => {
  const { type, url, id } = event.data || {};
  if (type === 'refresh') return void refresh();
  if (type === 'check') {
    if (!loaded) return self.postMessage({ type: 'check-result', id, error: '시그니처 데이터가 준비되지 않았습니다.' });
    try {
      // 정규화는 확장 프로그램의 공통 판정 엔진 안에서 수행한다.
      const normalized = normalizeUrl(url);
      const records = normalized ? (index.get(normalized) || []) : [];
      const result = evaluateUrl(url, records);
      self.postMessage({ type: 'check-result', id, result });
    } catch (e) {
      self.postMessage({ type: 'check-result', id, error: String(e?.message || e) });
    }
  }
};

refresh();
