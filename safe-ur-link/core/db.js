// 로컬 시그니처 DB (IndexedDB). 레코드 키: "소스|URL" → URL 인덱스로 소스별 레코드를 하나의 결과로 통합 조회
const NAME = 'safe-ur-link', STORE = 'sigs';
let dbp;
function open() {
  return dbp ||= new Promise((res, rej) => {
    const r = indexedDB.open(NAME, 1);
    r.onupgradeneeded = () => {
      const s = r.result.createObjectStore(STORE, { keyPath: 'id' });
      s.createIndex('url', 'url'); s.createIndex('source', 'source');
    };
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
const done = tx => new Promise((res, rej) => { tx.oncomplete = res; tx.onerror = tx.onabort = () => rej(tx.error); });
const reqp = r => new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });

// 기존 이력을 삭제하지 않고 소스+URL 키로 추가/갱신한다.
// 작은 배치별 트랜잭션을 사용하므로 대용량 갱신이 실패하더라도 기존 데이터는 삭제되지 않는다.
export async function mergeRecords(records, batchSize = 2500) {
  const db = await open();
  let written = 0;
  for (let start = 0; start < records.length; start += batchSize) {
    const tx = db.transaction(STORE, 'readwrite');
    const st = tx.objectStore(STORE);
    for (let i = start; i < Math.min(records.length, start + batchSize); i++) {
      const r = records[i];
      st.put({ id: `${r.source}|${r.url}`, url: r.url, source: r.source, meta: r.meta || {} });
      written++;
    }
    await done(tx);
  }
  return written;
}

// 구버전 브라우저 DB에만 존재하는 항목도 삭제 대신 과거 이력으로 전환한다.
// 이번 수집이 'updated'인 출처만 대상으로 하며, 실패한 소스(retained)는 건드리지 않는다.
export async function deactivateMissing(records, sourceStatus, previousGeneratedAt) {
  const succeeded = Object.entries(sourceStatus || {})
    .filter(([, s]) => s?.state === 'updated').map(([name]) => name);
  if (!succeeded.length) return 0;
  const listed = new Set(records.map(r => `${r.source}|${r.url}`));
  const db = await open();
  let archived = 0;
  for (const source of succeeded) {
    const tx = db.transaction(STORE, 'readwrite');
    const req = tx.objectStore(STORE).index('source').openCursor(IDBKeyRange.only(source));
    req.onsuccess = () => {
      const cursor = req.result;
      if (!cursor) return;
      if (!listed.has(cursor.primaryKey) && cursor.value.meta?.active !== false) {
        cursor.update({ ...cursor.value, meta: {
          ...cursor.value.meta, active: false,
          lastObservedAt: cursor.value.meta?.lastObservedAt || previousGeneratedAt || undefined
        }});
        archived++;
      }
      cursor.continue();
    };
    await done(tx);
  }
  return archived;
}

// 시연용 Demo 데이터는 실제 피드가 처음 수집되었을 때에만 정리한다.
export async function clearDemo() {
  const db = await open();
  const tx = db.transaction(STORE, 'readwrite');
  const st = tx.objectStore(STORE);
  const req = st.index('source').openKeyCursor(IDBKeyRange.only('Demo'));
  req.onsuccess = () => {
    const cursor = req.result;
    if (cursor) { st.delete(cursor.primaryKey); cursor.continue(); }
  };
  await done(tx);
}

export async function lookup(url) {
  const db = await open();
  return reqp(db.transaction(STORE).objectStore(STORE).index('url').getAll(url));
}
export async function all() {
  const db = await open();
  return reqp(db.transaction(STORE).objectStore(STORE).getAll());
}
export async function countBySource() {
  const db = await open(); const st = db.transaction(STORE).objectStore(STORE).index('source');
  const out = {};
  for (const s of ['URLhaus', 'PhishTank', 'PhishingDB', 'ThreatFox', 'Demo']) out[s] = await reqp(st.count(IDBKeyRange.only(s)));
  return out;
}
