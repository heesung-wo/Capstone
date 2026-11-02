import test from 'node:test';
import assert from 'node:assert/strict';
import { urlhaus, phishtank, phishingDatabase, threatfox, REFRESH_MS, PHISHTANK_ANONYMOUS_MS, PHISHTANK_PUBLIC_CSV_GZ, PHISHTANK_PUBLIC_JSON_GZ, PHISHING_DB_URL, PHISHING_DB_FALLBACK_URL } from '../core/feeds.js';

function mock(body, status = 200, headers = {}) {
  return async (url, init = {}) => {
    globalThis.lastRequest = { url, init };
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers });
  };
}

test('URLhaus needs auth key', async () => {
  await assert.rejects(urlhaus({ authKey: '' }), /Auth-Key/);
});

test('URLhaus CSV parser preserves online status and real dateadded', async () => {
  globalThis.fetch = mock(`# generated\n"id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"\n"1","2026-10-20 13:10:00 UTC","https://evil.invalid/a","online","None","malware_download","x,y","https://ref.invalid","a"\n"2","2026-10-19 12:10:00 UTC","http://evil.invalid/b","offline","2026-10-21 12:10:00 UTC","malware_download","z","https://ref.invalid","b"`);
  const found = await urlhaus({ authKey: 'mock-key' });
  assert.equal(found.length, 2);
  assert.equal(found[0].meta.online, true);
  assert.equal(found[1].meta.online, false);
  assert.equal(found[0].meta.first_seen, '2026-10-20T13:10:00.000Z');
  assert.deepEqual(found[0].meta.tags, ['x','y']);
  assert.equal(lastRequest.url, 'https://urlhaus-api.abuse.ch/v2/files/exports/mock-key/recent.csv');
});

test('URLhaus CSV also handles legacy unheaded 9-field export', async () => {
  globalThis.fetch = mock('# comment\n"42","2026-10-01 10:00:00 UTC","http://evil.invalid/load","online","None","malware_download","Z","x","x"');
  const items = await urlhaus({ authKey: 'key' });
  assert.equal(items[0].url, 'http://evil.invalid/load');
});

test('PhishTank: API 키 없이 압축 CSV 다운로드, 검증·활성 URL만 수집', async () => {
  const { gzipSync } = await import('node:zlib');
  const csv = 'phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n' +
    '1,https://bad.invalid/login,details,2026-10-10T00:00:00+00:00,yes,2026-10-11T00:00:00+00:00,yes,"Fake, Brand"\n' +
    '2,https://inactive.invalid/,details,,yes,,no,Fake\n' +
    '3,ftp://unsupported.invalid/,details,,yes,,yes,Fake\n';
  globalThis.fetch = async (url, init) => { globalThis.lastRequest = { url, init }; return new Response(gzipSync(csv)); };
  const found = await phishtank();
  assert.equal(found.length, 1);
  assert.equal(found[0].url, 'https://bad.invalid/login');
  assert.equal(found[0].meta.target, 'Fake, Brand');
  assert.equal(found[0].meta.verified, true);
  assert.equal(found[0].meta.online, true);
  assert.equal(found[0].meta.first_seen, '2026-10-10T00:00:00.000Z');
  assert.equal(lastRequest.url, PHISHTANK_PUBLIC_CSV_GZ);
  assert.equal(lastRequest.init.headers['User-Agent'], 'phishtank/safe-ur-link-capstone');
});

test('PhishTank: 이미 HTTP에서 압축 해제된 CSV도 파싱', async () => {
  globalThis.fetch = mock('phish_id,url,verified,online\n1,https://bad.invalid/,yes,yes\n');
  const found = await phishtank({ userAgent: 'phishtank/capstone-application' });
  assert.equal(found.length, 1);
  assert.equal(lastRequest.init.headers['User-Agent'], 'phishtank/capstone-application');
});

test('PhishTank: HTML 차단 응답은 데이터로 저장하지 않는다', async () => {
  globalThis.fetch = mock('<html>Cloud challenge</html>');
  await assert.rejects(phishtank(), /HTML/);
});

test('ThreatFox requires key, queries 7 days, preserves first_seen', async () => {
  await assert.rejects(threatfox({}), /Auth-Key/);
  globalThis.fetch = mock({query_status:'ok', data:[
    {ioc_type:'url',ioc:'https://bad.invalid/exec',confidence_level:85,first_seen:'2026-10-15 01:02:03 UTC'},
    {ioc_type:'domain',ioc:'bad.invalid'}
  ]});
  const items = await threatfox({ authKey:'test' });
  assert.equal(items.length,1);
  assert.equal(items[0].meta.first_seen,'2026-10-15T01:02:03.000Z');
  assert.equal(items[0].meta.verified,false);
  assert.equal(lastRequest.init.headers['Auth-Key'],'test');
  assert.equal(JSON.parse(lastRequest.init.body).days,7);
});

test('PhishingDB: 공식 주소에서 URL만 읽고 주석/빈 줄/비 http 줄은 무시한다', async () => {
  globalThis.fetch = mock('https://bad.invalid/\n# test\n\nftp://x.invalid/a\nnot a url\nhttps://bad2.invalid/a');
  const items = await phishingDatabase();
  assert.equal(PHISHING_DB_URL, 'https://phish.co.za/latest/phishing-links-ACTIVE.txt');
  assert.equal(lastRequest.url, PHISHING_DB_URL);
  assert.equal(items.length, 2);
});

test('PhishingDB: 제공되지 않는 first_seen/verified/online을 만들어 내지 않는다', async () => {
  globalThis.fetch = mock('https://bad.invalid/');
  const [item] = await phishingDatabase();
  assert.equal(item.meta.first_seen, undefined);
  assert.equal(item.meta.verified, undefined);
  assert.equal(item.meta.online, undefined);
  assert.equal(item.meta.threat, 'phishing');
});

test('PhishingDB: User-Agent는 지정했을 때만 보낸다', async () => {
  globalThis.fetch = mock('https://bad.invalid/');
  await phishingDatabase({ userAgent: 'my-agent' });
  assert.equal(lastRequest.init.headers['User-Agent'], 'my-agent');
  await phishingDatabase();
  assert.equal(lastRequest.init.headers, undefined);
});

test('PhishingDB: HTML 응답이나 빈 파일은 오류', async () => {
  globalThis.fetch = mock('<html>blocked</html>');
  await assert.rejects(phishingDatabase(), /HTML/);
  globalThis.fetch = mock('# only comments\n');
  await assert.rejects(phishingDatabase(), /유효한 URL/);
});

test('PhishTank: HTTP 509 호출 제한 시 다른 주소로 재시도하지 않는다', async () => {
  let requests = 0;
  globalThis.fetch = async () => { requests++; return new Response('blocked', { status: 509 }); };
  await assert.rejects(phishtank({}), /509.*호출 제한/);
  assert.equal(requests, 1);
});

test('refresh limits are conservative for unauthenticated feed', () => {
  assert.equal(REFRESH_MS.URLhaus, 60*60_000);
  assert.equal(REFRESH_MS.PhishTank, 24*60*60_000);
  assert.equal(PHISHTANK_ANONYMOUS_MS, 24*60*60_000);
});

test('PhishingDB: 공식 피드가 403이면 GitHub 원본으로 대체한다', async () => {
  const urls = [];
  globalThis.fetch = async (url) => {
    urls.push(url);
    if (url === PHISHING_DB_URL) return new Response('Access Denied', {status: 403});
    if (url === PHISHING_DB_FALLBACK_URL) return new Response('https://backup.invalid/login\n# comment\n');
    throw new Error('예상하지 못한 URL');
  };
  const items = await phishingDatabase();
  assert.deepEqual(urls, [PHISHING_DB_URL, PHISHING_DB_FALLBACK_URL]);
  assert.equal(items.length, 1);
  assert.equal(items[0].url, 'https://backup.invalid/login');
  assert.equal(items[0].meta.online, undefined);
});

test('PhishingDB: 두 피드 모두 실패하면 원인과 경로를 알 수 있도록 오류 처리', async () => {
  globalThis.fetch = async (url) => new Response('error', { status: url === PHISHING_DB_URL ? 503 : 404 });
  await assert.rejects(phishingDatabase(), /공식 피드: HTTP 503.*GitHub 원본: HTTP 404/);
});


test('PhishTank: CSV 404일 때만 공식 공개 gzip JSON으로 1회 대체', async () => {
  const { gzipSync } = await import('node:zlib');
  const urls = [];
  globalThis.fetch = async (url, init) => {
    urls.push(url);
    assert.ok(init.headers['User-Agent'].startsWith('phishtank/'));
    if (url === PHISHTANK_PUBLIC_CSV_GZ) return new Response('missing', { status: 404 });
    return new Response(gzipSync(JSON.stringify([
      { url: 'https://fallback.invalid/login', verified: 'yes', online: 'yes' }
    ])));
  };
  const found = await phishtank();
  assert.deepEqual(urls, [PHISHTANK_PUBLIC_CSV_GZ, PHISHTANK_PUBLIC_JSON_GZ]);
  assert.equal(found.length, 1);
  assert.equal(found[0].url, 'https://fallback.invalid/login');
});

test('PhishTank: 404 두 번이면 실패 원인이 로그에 표시된다', async () => {
  globalThis.fetch = async () => new Response('missing', { status: 404 });
  await assert.rejects(phishtank(), /HTTP 404/);
});

test('PhishTank: 503은 호출 제한을 고려해 경로를 추가로 시도하지 않는다', async () => {
  let requests = 0;
  globalThis.fetch = async () => { requests++; return new Response('offline', { status: 503 }); };
  await assert.rejects(phishtank(), /HTTP 503/);
  assert.equal(requests, 1);
});
