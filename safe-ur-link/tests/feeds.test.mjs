import test from 'node:test';
import assert from 'node:assert/strict';
import { urlhaus, phishtank, openphish, threatfox, REFRESH_MS, PHISHTANK_ANONYMOUS_MS } from '../core/feeds.js';

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

test('OpenPhish does not invent first_seen timestamp', async () => {
  globalThis.fetch = mock('https://bad.invalid/\n# test\n\nhttps://bad2.invalid/a');
  const items = await openphish();
  assert.equal(items.length,2);
  assert.equal(items[0].meta.first_seen,undefined);
});

test('HTTP 509 surfaces as rate limit', async () => {
  globalThis.fetch = mock('blocked',509);
  await assert.rejects(phishtank({}), /509.*호출 제한/);
});

test('refresh limits are conservative', () => {
  assert.equal(REFRESH_MS.URLhaus,60*60_000);
  assert.equal(PHISHTANK_ANONYMOUS_MS,24*60*60_000);
});
