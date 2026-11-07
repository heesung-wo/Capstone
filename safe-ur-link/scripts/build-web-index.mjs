// 전체 시그니처 원본은 그대로 배포하고, 웹사이트 직접 검사용 경량 샤드 인덱스를 추가 생성한다.
// 웹 브라우저가 약 100만 건을 한 번에 내려받아 파싱/색인하는 작업을 피하기 위한 구조.
import { readFile, writeFile, mkdir, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WEB_SHARD_COUNT, shardForUrl } from '../core/web-shards.js';

const root = fileURLToPath(new URL('../public/', import.meta.url));

export function buildWebIndex(feed, shardCount = WEB_SHARD_COUNT) {
  if (feed?.schema !== 1 || !Number.isFinite(Date.parse(feed.generatedAt)) || !Array.isArray(feed.signatures)) {
    throw new Error('시그니처 피드 형식이 올바르지 않습니다.');
  }
  const shards = Array.from({ length: shardCount }, () => []);
  const sourceCounts = {};
  for (const row of feed.signatures) {
    if (!row || typeof row.url !== 'string' || typeof row.source !== 'string') {
      throw new Error('시그니처 레코드가 올바르지 않습니다.');
    }
    shards[shardForUrl(row.url, shardCount)].push(row);
    sourceCounts[row.source] = (sourceCounts[row.source] || 0) + 1;
  }
  // 같은 URL이 여러 소스에 있는 경우 고유 URL 수만 한 번 센다.
  let uniqueCount = 0;
  for (const rows of shards) uniqueCount += new Set(rows.map(row => row.url)).size;
  return {
    manifest: {
      schema: 1,
      format: 'safeurlink-shards-v1',
      generatedAt: feed.generatedAt,
      shardCount,
      signatureCount: feed.signatures.length,
      uniqueCount,
      sourceCounts,
      demoOnly: feed.signatures.length > 0 && feed.signatures.every(row => row.source === 'Demo')
    },
    shards
  };
}

export async function writeWebIndex(feed, output = root, shardCount = WEB_SHARD_COUNT) {
  const { manifest, shards } = buildWebIndex(feed, shardCount);
  const dir = path.join(output, 'web-shards');
  await mkdir(dir, { recursive: true });
  // 이전 배포의 샤드 개수가 바뀐 경우에도 오래된 파일이 섞이지 않도록 지운다.
  for (const name of await readdir(dir)) {
    if (/^\d+\.json$/.test(name)) await rm(path.join(dir, name));
  }
  for (let id = 0; id < shards.length; id++) {
    // 샤드마다 생성 버전을 포함해 manifest와 다른 빌드 결과가 섞인 경우 탐지 가능하게 한다.
    const data = { schema: 1, generatedAt: manifest.generatedAt, shard: id, signatures: shards[id] };
    await writeFile(path.join(dir, `${id}.json`), JSON.stringify(data));
  }
  // 파일은 마지막에 생성한다. 이 시점에 모든 샤드 생성이 완료되어 있다.
  await writeFile(path.join(output, 'web-index.json'), JSON.stringify(manifest));
  return manifest;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const feed = JSON.parse(await readFile(path.join(root, 'signatures.json'), 'utf8'));
  const manifest = await writeWebIndex(feed);
  console.log(`웹 인덱스 생성 완료: 시그니처 ${manifest.signatureCount.toLocaleString()}건, ${manifest.shardCount}개 샤드`);
}
