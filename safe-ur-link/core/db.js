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

export async function replaceSource(source, items) {   // items: [{url, meta}]
  const db = await open(); const tx = db.transaction(STORE, 'readwrite'); const st = tx.objectStore(STORE);
  st.delete(IDBKeyRange.bound(source + '|', source + '|\uffff'));
  for (const it of items) st.put({ id: `${source}|${it.url}`, url: it.url, source, meta: it.meta });
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
  for (const s of ['URLhaus', 'PhishTank', 'OpenPhish', 'ThreatFox']) out[s] = await reqp(st.count(IDBKeyRange.only(s)));
  return out;
}
