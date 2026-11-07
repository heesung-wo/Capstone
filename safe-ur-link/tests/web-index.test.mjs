import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { normalizeUrl } from '../core/common.js';
import { evaluateUrl } from '../core/scan.js';
import { shardForUrl } from '../core/web-shards.js';
import { buildWebIndex, writeWebIndex } from '../scripts/build-web-index.mjs';

const feed = JSON.parse(await readFile(new URL('../public/signatures.json', import.meta.url), 'utf8'));

test('샤드로 나눠도 원본 모든 시그니처가 정확히 한 번 존재한다', () => {
  const { manifest, shards } = buildWebIndex(feed);
  assert.equal(shards.length, 512);
  assert.equal(manifest.signatureCount, feed.signatures.length);
  const joined = shards.flat();
  assert.deepEqual(joined.map(r => r.url).sort(), feed.signatures.map(r => r.url).sort());
  assert.equal(manifest.demoOnly, true);
  assert.equal(manifest.uniqueCount, 2);
  for (const row of feed.signatures) assert.ok(shards[shardForUrl(row.url)].some(r => r.url === row.url));
});

test('하나의 URL이 여러 데이터 소스에 등록되어도 정확히 같은 샤드에서 교차 탐지한다', () => {
  const url = 'https://many.example.org/suspicious';
  const multi = {
    schema: 1,
    generatedAt: new Date().toISOString(),
    signatures: [
      { url, source: 'URLhaus', meta: { online: true } },
      { url, source: 'PhishTank', meta: { verified: true, valid: true } },
      { url: 'https://normal.example.org/', source: 'PhishingDB', meta: {} }
    ]
  };
  const { manifest, shards } = buildWebIndex(multi);
  const matching = shards[shardForUrl(normalizeUrl(url))].filter(r => r.url === url);
  assert.equal(manifest.uniqueCount, 2);
  assert.equal(manifest.signatureCount, 3);
  assert.equal(evaluateUrl(url, matching).externalScore, 46);
  assert.deepEqual(evaluateUrl(url, matching).sources, ['URLhaus', 'PhishTank']);
});

test('시그니처를 2,000건으로 늘려도 필요한 샤드만 일치시키며 전체 개수를 보존한다', () => {
  const signatures = Array.from({ length: 2000 }, (_, i) => ({
    url: `https://host${i}.example.invalid/path/${i}`, source: 'PhishingDB', meta: { verified: true }
  }));
  const { manifest, shards } = buildWebIndex({ schema: 1, generatedAt: new Date().toISOString(), signatures });
  assert.equal(manifest.signatureCount, 2000);
  assert.equal(manifest.uniqueCount, 2000);
  assert.ok(Math.max(...shards.map(s => s.length)) < 30);
  const target = signatures[871];
  assert.equal(shards[shardForUrl(target.url)].filter(r => r.url === target.url).length, 1);
});

test('배포 시 모든 샤드와 경량 인덱스를 생성하고 생성 시각을 고정한다', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'safeurlink-shards-'));
  try {
    const manifest = await writeWebIndex(feed, dir, 16);
    const fromDisk = JSON.parse(await readFile(path.join(dir, 'web-index.json'), 'utf8'));
    assert.deepEqual(fromDisk, manifest);
    const shard = shardForUrl('https://phishing.test/login', 16);
    const data = JSON.parse(await readFile(path.join(dir, 'web-shards', `${shard}.json`), 'utf8'));
    assert.equal(data.generatedAt, feed.generatedAt);
    assert.equal(data.shard, shard);
    assert.equal(data.signatures.some(r => r.url === 'https://phishing.test/login'), true);
  } finally { await rm(dir, { recursive: true, force: true }); }
});


test('대량 데이터 50,000건도 표본 추출 없이 전부 샤드에 보존한다', () => {
  const signatures = Array.from({ length: 50_000 }, (_, i) => ({
    url: `https://bulk${i}.sample.invalid/path/${i}`,
    source: i % 2 ? 'PhishingDB' : 'URLhaus',
    meta: { online: i % 3 === 0, active: true }
  }));
  const { manifest, shards } = buildWebIndex({ schema: 1, generatedAt: new Date().toISOString(), signatures });
  assert.equal(manifest.signatureCount, signatures.length);
  assert.equal(shards.reduce((sum, rows) => sum + rows.length, 0), 50_000);
  assert.equal(manifest.uniqueCount, 50_000);
  for (const i of [0, 1, 870, 12_500, 49_999]) {
    const row = signatures[i];
    assert.equal(shards[shardForUrl(row.url)].filter(r => r.url === row.url).length, 1);
  }
});
