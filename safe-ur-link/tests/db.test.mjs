import test from 'node:test';
import assert from 'node:assert/strict';

// 메모리 기반 IndexedDB 모사: 실제 브라우저 통합 테스트를 대체하지 않는다.
const stored = new Map();
const db = {
  transaction() {
    let cursorMode = false;
    const tx = {
      oncomplete: null, onerror: null, onabort: null,
      objectStore() {
        return {
          put(record) { stored.set(record.id, record); },
          index() { return {
            openCursor(range) {
              cursorMode = true;
              const keys = [...stored.keys()].filter(k => stored.get(k).source === range.source);
              const req = { result: null, onsuccess: null };
              let position = 0;
              const step = () => {
                const primaryKey = keys[position];
                req.result = primaryKey === undefined ? null : {
                  primaryKey, value: stored.get(primaryKey),
                  update(record) { stored.set(primaryKey, record); },
                  continue() { position++; queueMicrotask(step); }
                };
                req.onsuccess?.();
                if (!req.result) queueMicrotask(() => tx.oncomplete?.());
              };
              queueMicrotask(step);
              return req;
            }
          }; }
        };
      }
    };
    queueMicrotask(() => { if (!cursorMode) tx.oncomplete?.(); });
    return tx;
  }
};
globalThis.indexedDB = { open() { const req = { result: db }; queueMicrotask(() => req.onsuccess?.()); return req; } };
globalThis.IDBKeyRange = { only(source) { return { source }; } };
const {mergeRecords, deactivateMissing} = await import('../core/db.js');

test('DB UPSERT: 기존에 없는 URL도 삭제 없이 유지되고 동일 출처 키는 갱신됨', async () => {
  const a = { source: 'URLhaus', url: 'https://a.invalid/', meta: { active: true } };
  const b = { source: 'URLhaus', url: 'https://b.invalid/', meta: { active: true } };
  await mergeRecords([a, b], 1);
  await mergeRecords([{ ...b, meta: { active: false } }, {source:'ThreatFox',url:'https://c.invalid/',meta:{active:true}}], 1);
  assert.equal(stored.size, 3);
  assert.equal(stored.get('URLhaus|https://a.invalid/').meta.active, true);
  assert.equal(stored.get('URLhaus|https://b.invalid/').meta.active, false);
  assert.equal(stored.get('ThreatFox|https://c.invalid/').meta.active, true);
});

test('구버전 로컬 데이터도 정상 갱신 소스에서만 과거 이력으로 전환하고 실패 소스는 변경하지 않음', async () => {
  await mergeRecords([
    { source: 'URLhaus', url: 'https://old.invalid/', meta: { active: true } },
    { source: 'URLhaus', url: 'https://current.invalid/', meta: { active: true } },
    { source: 'PhishingDB', url: 'https://preserved.invalid/', meta: { active: true } }
  ]);
  const count = await deactivateMissing(
    [{ source: 'URLhaus', url: 'https://current.invalid/', meta: {active:true} }],
    {URLhaus:{state:'updated'},PhishingDB:{state:'retained'}},
    '2026-11-01T00:00:00Z'
  );
  assert.equal(count, 2); // 앞선 테스트의 a.invalid 포함
  assert.equal(stored.get('URLhaus|https://old.invalid/').meta.active,false);
  assert.equal(stored.get('URLhaus|https://current.invalid/').meta.active,true);
  assert.equal(stored.get('PhishingDB|https://preserved.invalid/').meta.active,true);
});
