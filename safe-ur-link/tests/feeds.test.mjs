import test from 'node:test';
import assert from 'node:assert/strict';
import { urlhaus, phishtank, phishingDatabase, threatfox, REFRESH_MS, PHISHTANK_ANONYMOUS_MS, PHISHING_DB_URL, PHISHING_DB_FALLBACK_URL } from '../core/feeds.js';

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

test('PhishTank JSON supports anonymous feed, yields actual metadata', async () => {
  globalThis.fetch = mock([{url:'https://bad.invalid/login',verified:'yes',online:'yes',target:'Example',submission_time:'2026-10-10T00:00:00+00:00'}]);
  const found = await phishtank({});
  assert.equal(found.length,1);
  assert.equal(found[0].meta.verified,true);
  assert.equal(found[0].meta.valid,true); // online-valid 피드에 포함된 URL
  assert.equal(found[0].meta.first_seen,'2026-10-10T00:00:00.000Z');
  assert.equal(lastRequest.url,'https://data.phishtank.com/data/online-valid.json');
});

test('PhishTank rejects challenge HTML instead of wiping DB', async () => {
  globalThis.fetch = mock('<html>Cloud challenge</html>');
  await assert.rejects(phishtank({}), /HTML/);
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

test('HTTP 509 surfaces as rate limit', async () => {
  globalThis.fetch = mock('blocked',509);
  await assert.rejects(phishtank({}), /509.*호출 제한/);
});

test('refresh limits are conservative', () => {
  assert.equal(REFRESH_MS.URLhaus,60*60_000);
  assert.equal(PHISHTANK_ANONYMOUS_MS,24*60*60_000);
});

test('PhishTank sends custom User-Agent only when provided (server-side build)', async () => {
  globalThis.fetch = mock([{ url: 'https://bad.invalid/x', verified: 'yes', online: 'yes' }]);
  await phishtank({ userAgent: 'phishtank/test-user' });
  assert.equal(lastRequest.init.headers['User-Agent'], 'phishtank/test-user');
  await phishtank({});
  assert.equal(lastRequest.init.headers, undefined);
});


test('PhishTank: 인증 JSON 404이면 인증 CSV로 넘어가고 모든 URL을 가져온다', async () => {
  const requested = [];
  const logs = [];
  globalThis.fetch = async (url) => {
    requested.push(url);
    if (url.endsWith('.json')) return new Response('Not Found', {status:404});
    return new Response('phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n42,https://bad.invalid/login,x,2026-10-01T00:00:00+00:00,yes,,yes,Test', {status:200});
  };
  const found = await phishtank({phishKey:'demo-key',onFallback:x=>logs.push(x)});
  assert.equal(found.length,1);
  assert.equal(found[0].meta.valid,true);
  assert.equal(found[0].meta.online,true);
  assert.equal(requested.length,2);
  assert.equal(requested[1], 'https://data.phishtank.com/data/demo-key/online-valid.csv');
  assert.ok(logs.some(l => /HTTP 404/.test(l)));
  assert.ok(logs.every(l => !l.includes('demo-key')));
});

test('PhishTank: 인증 경로 모두 404이면 공개 공식 경로를 확인한다', async () => {
  const requested = [];
  globalThis.fetch = async url => {
    requested.push(url);
    if (url.includes('/secret/')) return new Response('',{status:404});
    return new Response(JSON.stringify([{url:'https://bad.invalid/now',verified:'yes',online:'yes'}]));
  };
  const items = await phishtank({phishKey:'secret'});
  assert.equal(items.length,1);
  assert.equal(requested.length,3);
  assert.equal(requested[2], 'https://data.phishtank.com/data/online-valid.json');
});

test('PhishTank: 401/403/429/509이면 다른 주소로 우회하지 않는다', async () => {
  for (const status of [401,403,429,509]) {
    let count=0;
    globalThis.fetch = async () => { count++; return new Response('error', {status}); };
    await assert.rejects(phishtank({phishKey:'secret'}), new RegExp('HTTP '+status));
    assert.equal(count,1);
  }
});

test('PhishTank: 모든 404를 명확한 설정 오류로 알린다', async () => {
  globalThis.fetch = async () => new Response('not found', {status:404});
  await assert.rejects(phishtank({phishKey:'secret'}), /다운로드 경로가 모두 HTTP 404/);
});

test('PhishingDB: 공식 서버 503이면 GitHub 원본으로 대체한다', async () => {
  const logs=[]; const requests=[];
  globalThis.fetch = async url => {
    requests.push(url);
    return url === PHISHING_DB_URL
      ? new Response('unavailable',{status:503})
      : new Response('https://evil.invalid/a\nhttps://evil.invalid/b\n');
  };
  const items = await phishingDatabase({onFallback:x=>logs.push(x)});
  assert.equal(PHISHING_DB_FALLBACK_URL, 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt');
  assert.deepEqual(requests, [PHISHING_DB_URL, PHISHING_DB_FALLBACK_URL]);
  assert.equal(items.length,2);
  assert.ok(logs.some(x=>/HTTP 503/.test(x)));
});

test('PhishingDB: 공식 서버 429는 우회하지 않는다', async () => {
  let count=0;
  globalThis.fetch = async () => {count++;return new Response('limit',{status:429});};
  await assert.rejects(phishingDatabase(), /HTTP 429/);
  assert.equal(count,1);
});

test('PhishingDB: 대체 경로도 실패하면 오류와 httpStatus를 유지한다', async () => {
  globalThis.fetch = async url => new Response('oops', {status:url === PHISHING_DB_URL ? 503:502});
  await assert.rejects(phishingDatabase(), e => e.httpStatus === 502 && /대체 주소도 실패/.test(e.message));
});

test('PhishingDB: 공식 서버 연결 실패에서도 GitHub 원본으로 재시도한다', async () => {
  const calls=[];
  globalThis.fetch = async url => {
    calls.push(url);
    if (url === PHISHING_DB_URL) throw new Error('connection reset');
    return new Response('https://recovered.invalid/\n', {status:200});
  };
  const rows=await phishingDatabase();
  assert.equal(rows[0].url,'https://recovered.invalid/');
  assert.deepEqual(calls,[PHISHING_DB_URL, PHISHING_DB_FALLBACK_URL]);
});

test('PhishingDB: HTTP 200이지만 HTML 오류 페이지면 GitHub 대체 주소를 사용한다', async () => {
  globalThis.fetch = async url => url === PHISHING_DB_URL
    ? new Response('<!doctype html><html>maintenance</html>',{status:200})
    : new Response('https://recovered.invalid/\n',{status:200});
  const rows=await phishingDatabase();
  assert.equal(rows.length,1);
  assert.equal(rows[0].url,'https://recovered.invalid/');
});
