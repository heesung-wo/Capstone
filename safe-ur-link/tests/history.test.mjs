import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeHistory } from '../core/history.js';
import { buildFeed, loadPreviousFeed } from '../scripts/build-feed.mjs';
import { validateFeed } from '../core/remote-feed.js';
import { buildProtectionRules } from '../core/dnr.js';

const t1 = '2026-11-02T00:00:00.000Z';
const t2 = '2026-11-05T00:00:00.000Z';
const make = (url, source='URLhaus', meta={}) => ({ url, source, meta });
const mkPrevious = signatures => ({ schema: 1, generatedAt: t1, signatures });
const env = { REDISTRIBUTION_CONFIRMED: 'true', PUBLISH_URLHAUS: 'true', PUBLISH_PHISHING_DB: 'true', OPTIONAL_SOURCES: 'PhishingDB' };

const byUrl = (items,url,source='URLhaus') => items.find(x => x.url === url && x.source === source);

test('A,B → B,C: 과거 A 유지, 최신 B 갱신, 신규 C 추가', () => {
  const old = [make('https://a.invalid/','URLhaus',{online:true}), make('https://b.invalid/','URLhaus',{online:false})];
  const fresh = [make('https://b.invalid/','URLhaus',{online:true}), make('https://c.invalid/','URLhaus',{online:true})];
  const items = mergeHistory(old,fresh,['URLhaus'],t2,t1);
  assert.equal(items.length,3);
  assert.equal(byUrl(items,'https://a.invalid/').meta.active,false);
  assert.equal(byUrl(items,'https://a.invalid/').meta.lastObservedAt,t1);
  assert.equal(byUrl(items,'https://b.invalid/').meta.active,true);
  assert.equal(byUrl(items,'https://b.invalid/').meta.online,true);
  assert.equal(byUrl(items,'https://b.invalid/').meta.lastObservedAt,t2);
  assert.equal(byUrl(items,'https://c.invalid/').meta.active,true);
});

test('소스 장애: 기존 URL과 online/active/확인시각 모두 유지', () => {
  const old = [make('https://p.invalid/','PhishingDB',{active:true, online:false, lastObservedAt:t1})];
  const fresh = [make('https://u.invalid/')];
  const items = mergeHistory(old,fresh,['URLhaus'],t2,t1);
  assert.deepEqual(byUrl(items,'https://p.invalid/','PhishingDB'),old[0]);
});

test('동일 URL의 URLhaus만 최신 목록에서 빠지고 PhishingDB는 수집 실패할 수 있다', () => {
  const shared='https://shared.invalid/';
  const old = [make(shared,'URLhaus',{active:true}),make(shared,'PhishingDB',{active:true})];
  const items = mergeHistory(old,[],['URLhaus'],t2,t1);
  assert.equal(byUrl(items,shared,'URLhaus').meta.active,false);
  assert.equal(byUrl(items,shared,'PhishingDB').meta.active,true);
});

test('서버 누적 배포: 선택 소스 장애가 있더라도 지난 PhishingDB 이력을 재공개하고 라이선스 고지 보존', async () => {
  const previous = mkPrevious([
    make('https://urlhaus-old.invalid/','URLhaus',{online:true}),
    make('https://phish-old.invalid/','PhishingDB',{threat:'phishing'})
  ]);
  const collected = {
    URLhaus: async () => [make('https://urlhaus-new.invalid/','URLhaus',{online:true})],
    PhishingDB: async () => { throw Object.assign(new Error('HTTP 503'),{httpStatus:503}); }
  };
  const feed = await buildFeed(env,{ previousFeed:previous, collectors:collected, now:Date.parse(t2), sleep:async()=>{} });
  assert.equal(feed.signatures.length,3);
  assert.equal(byUrl(feed.signatures,'https://urlhaus-old.invalid/').meta.active,false);
  assert.equal(byUrl(feed.signatures,'https://urlhaus-new.invalid/').meta.active,true);
  assert.equal(byUrl(feed.signatures,'https://phish-old.invalid/','PhishingDB').meta.active,true);
  assert.equal(feed.sourceStatus.PhishingDB.state,'retained');
  assert.equal(feed.sourceStatus.URLhaus.state,'updated');
  assert.equal(feed.notices[0].source,'PhishingDB');
  assert.equal(validateFeed(feed).records.length,3);
});

test('2차 누적 갱신에서도 같은 URL은 중복되지 않으며 과거 기록 유지', async () => {
  const previous = mkPrevious([make('https://one.invalid/')]);
  const collected = {URLhaus:async()=>[make('https://two.invalid/')]};
  const env2={REDISTRIBUTION_CONFIRMED:'true',PUBLISH_URLHAUS:'true'};
  const feed2=await buildFeed(env2,{previousFeed:previous,collectors:collected,now:Date.parse(t2)});
  const feed3=await buildFeed(env2,{previousFeed:feed2,collectors:collected,now:Date.parse(t2)+1000});
  assert.equal(feed3.signatures.length,2);
  assert.equal(byUrl(feed3.signatures,'https://one.invalid/').meta.active,false);
});

test('누적 DB 2000건 중 실시간 보호에는 과거 기록을 제외', () => {
  const archived=Array.from({length:2000},(_,i)=>make(`https://a${i}.invalid/`,'URLhaus',{active:false,lastObservedAt:t1}));
  const recent=[make('https://active.invalid/','URLhaus',{active:true,lastObservedAt:new Date().toISOString()})];
  const {rules,stats}=buildProtectionRules({realtime:true,allow:[],block:[]},[...archived,...recent],'chrome-extension://id/pages/warning/warning.html');
  assert.equal(rules.filter(x=>x.action.type==='block').length,1);
  assert.equal(stats.historicalUrls,2000);
});

test('활성 상태이더라도 7일 넘게 확인되지 않으면 실시간 보호만 제외', () => {
  const stale=make('https://old.invalid/','PhishingDB',{active:true,lastObservedAt:'2025-01-01T00:00:00Z'});
  const {rules,stats}=buildProtectionRules({realtime:true,allow:[],block:[]},[stale],'chrome-extension://id/warning.html');
  assert.equal(rules.length,0); assert.equal(stats.staleUrls,1);
});

test('이전 배포 URL이 503이면 기존 데이터 보호를 위해 새 빌드 불허', async () => {
  await assert.rejects(loadPreviousFeed('https://example.invalid/signatures.json',async()=>new Response('',{status:503})),/503/);
});

test('이전 배포 URL이 404이면 명시적 최초 배포 설정 없이 조용히 초기화하지 않음', async () => {
  await assert.rejects(loadPreviousFeed('https://example.invalid/signatures.json',async()=>new Response('',{status:404})),/ALLOW_FIRST_DEPLOY/);
});

test('잘못된 배포 설정(false 전체)으로 과거 실제 DB를 Demo로 덮어쓰지 않음', async () => {
  await assert.rejects(buildFeed({}, {previousFeed:mkPrevious([make('https://real.invalid/')])}),/공개 설정이 모두 꺼져/);
});
