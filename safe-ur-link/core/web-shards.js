// 고정 URL 해시. 빌드 시 샤드 배치와 웹사이트 조회에서 같은 함수를 사용한다.
// URL 정규화는 호출자가 공용 normalizeUrl()로 수행해야 한다.
export const WEB_SHARD_COUNT = 512;

export function shardForUrl(url, shardCount = WEB_SHARD_COUNT) {
  if (!Number.isInteger(shardCount) || shardCount < 1 || shardCount > 4096 || (shardCount & (shardCount - 1)) !== 0) {
    throw new Error('샤드 개수는 1~4096의 2의 제곱수여야 합니다.');
  }
  let hash = 0x811c9dc5;
  for (let i = 0; i < url.length; i++) {
    hash ^= url.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  // FNV의 낮은 비트가 비슷한 URL 패턴에서 몰리지 않게 최종 avalanche 처리.
  hash ^= hash >>> 16;
  hash = Math.imul(hash, 0x85ebca6b) >>> 0;
  hash ^= hash >>> 13;
  hash = Math.imul(hash, 0xc2b2ae35) >>> 0;
  hash ^= hash >>> 16;
  return hash & (shardCount - 1);
}
