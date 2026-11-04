import test from 'node:test';
import assert from 'node:assert/strict';
import { buildProtectionRules, MAX_PROTECTION_RULES, MAX_SIGNATURE_RULES, MAX_BLOCK_HOSTS,
  validateHostLists, sessionAllowCondition } from '../core/dnr.js';

const page = 'chrome-extension://exampleid/pages/warning/warning.html';
const sig = (url, source='URLhaus', meta={}) => ({url, source, meta});
const build = (s={}, records=[]) => buildProtectionRules({ realtime: true, allow: [], block: [], ...s }, records, page);

test('기본 시연용 시그니처는 경고 페이지가 아닌 DNR block으로 처리한다', () => {
  const { rules, stats } = build();
  assert.equal(stats.signatureRules, 2);
  assert.deepEqual(rules.map(x => x.id), [1,2]);
  const r = rules.find(x => x.condition.urlFilter === '|https://phishing.test/login|');
  assert.deepEqual(r.action, {type:'block'});
  assert.equal(r.priority, 10);
  assert.deepEqual(r.condition.resourceTypes, ['main_frame']);
});

test('사용자가 직접 추가한 차단 도메인만 경고 페이지로 redirect한다', () => {
  const { rules, stats } = build({block:['example.com']});
  const r = rules.find(x => x.id === 100001);
  const pat = new RegExp(r.condition.regexFilter, 'i');
  assert.ok(pat.test('https://a.b.example.com/pay?a=1'));
  assert.ok(pat.test('http://example.com/'));
  assert.ok(!pat.test('https://example.com.evil.test/login'));
  assert.equal(r.action.type,'redirect');
  assert.equal(r.action.redirect.regexSubstitution, page+'#\\0');
  assert.equal(r.priority, 20);
  assert.equal(stats.userBlockRules, 1);
  assert.equal(rules.filter(x=>x.action.type==='redirect').length,1);
});

test('DB와 사용자 차단 목록에 동일 주소가 있으면 redirect 우선, 허용 목록은 우선 허용', () => {
  const { rules, stats } = build({allow:['allowed.test'], block:['blocked.test']}, [
    sig('https://allowed.test/login'), sig('https://blocked.test/pay'),
    sig('https://other.test/file','URLhaus'), sig('https://other.test/file','PhishTank')
  ]);
  assert.equal(stats.excludedByAllow, 1);
  assert.equal(stats.handledByUserBlock, 1);
  assert.equal(stats.userAllowRules, 1);
  assert.equal(stats.signatureRules, 1); // 실제 피드가 있으면 2개 Demo를 추가하지 않는다
  assert.equal(rules.filter(x => x.condition.urlFilter === '|https://other.test/file|').length, 1);
  assert.equal(rules.find(x => x.id === 200001).priority, 30);
  assert.ok(!rules.some(x => x.condition.urlFilter === '|https://blocked.test/pay|'));
  assert.ok(!rules.some(x => x.condition.urlFilter === '|https://allowed.test/login|'));
});

test('시그니처 block 상한 29,700개를 지키고 초과 건수를 보고한다', () => {
  const many = Array.from({length:MAX_PROTECTION_RULES + 50},(_,i)=>sig(`https://batch${i}.test/path`));
  const {rules,stats}=build({block:['blocked.test'], allow:['allowed.test']}, many);
  assert.equal(rules.length, MAX_SIGNATURE_RULES + 2);
  assert.equal(stats.signatureRules, MAX_SIGNATURE_RULES);
  assert.equal(stats.quotaOverflowUrls, many.length - MAX_SIGNATURE_RULES);
  assert.equal(stats.skippedUrls, many.length - MAX_SIGNATURE_RULES);
  assert.equal(rules.filter(r=>r.action.type==='block').length, MAX_SIGNATURE_RULES);
  assert.equal(rules.filter(r=>r.action.type==='redirect').length,1);
  assert.ok(rules.every(r => r.id <= MAX_PROTECTION_RULES || r.id >= 100001));
});

test('사용자 차단 300개와 시그니처 29,700개를 함께 등록한다', () => {
  const records = Array.from({length: MAX_SIGNATURE_RULES}, (_, i) => sig(`https://real${i}.invalid/bad`));
  const block = Array.from({length: MAX_BLOCK_HOSTS}, (_, i) => `manual${i}.test`);
  const { rules, stats } = build({ block }, records);
  assert.equal(rules.length, MAX_PROTECTION_RULES);
  assert.equal(stats.signatureRules, MAX_SIGNATURE_RULES);
  assert.equal(stats.userBlockRules, MAX_BLOCK_HOSTS);
  assert.equal(rules.filter(r => r.action.type === 'redirect').length, MAX_BLOCK_HOSTS);
  assert.equal(rules.filter(r => r.action.type === 'block').length, MAX_SIGNATURE_RULES);
});

test('300개 사용자 차단과 허용 규칙이 공존하면 시그니처를 줄여 전체 30,000개를 지킨다', () => {
  const records = Array.from({length: MAX_SIGNATURE_RULES}, (_, i) => sig(`https://real${i}.invalid/bad`));
  const block = Array.from({length: MAX_BLOCK_HOSTS}, (_, i) => `manual${i}.test`);
  const allow = Array.from({length: 7}, (_, i) => `allow${i}.test`);
  const { rules, stats } = build({ block, allow }, records);
  assert.equal(rules.length, MAX_PROTECTION_RULES);
  assert.equal(stats.signatureRules, MAX_SIGNATURE_RULES - allow.length);
  assert.equal(stats.userBlockRules, MAX_BLOCK_HOSTS);
  assert.equal(stats.userAllowRules, allow.length);
  assert.equal(stats.quotaOverflowUrls, allow.length);
});

test('실제 피드가 있을 때에는 시연용 URL을 block 슬롯에 추가하지 않는다', () => {
  const {rules, stats} = build({}, [sig('https://genuine.invalid/url')]);
  assert.equal(stats.candidateUrls, 1);
  assert.equal(stats.signatureRules, 1);
  assert.ok(!rules.some(r => r.condition.urlFilter?.includes('phishing.test')));
});

test('교차 탐지 및 온라인 URL을 우선 등록한다', () => {
  const low = Array.from({length: MAX_PROTECTION_RULES}, (_,i) => sig(`https://low${i}.test/`));
  const high = [sig('https://important.test/','URLhaus', {online:true}),
    sig('https://important.test/','PhishTank',{verified:true})];
  const { rules } = build({}, low.concat(high));
  assert.ok(rules.some(r => r.condition.urlFilter === '|https://important.test/|' && r.action.type === 'block'));
});

test('실시간 보호를 끄면 사용자 차단 및 피드 규칙을 모두 제거한다', () => {
  const {rules,stats} = build({realtime:false,block:['example.com']}, [sig('https://evil.test/')]);
  assert.deepEqual(rules,[]);
  assert.equal(stats.total,0);
});

test('유효하지 않은 도메인, 사용자 차단 300개 초과 등 제한을 거부한다', () => {
  assert.throws(() => validateHostLists(['bad name'],[]), /올바르지 않은/);
  const many = Array.from({length:MAX_BLOCK_HOSTS+1}, (_,i)=>`block${i}.test`);
  assert.throws(() => build({block:many}), /최대 300개/);
});

test('DNR 필터 메타 문자를 포함하면 과잉 차단 규칙 대신 DB 검사만 사용한다', () => {
  const {rules,stats} = build({}, [sig('https://bad.test/*')]);
  assert.equal(stats.unsupportedUrls,1);
  assert.equal(stats.skippedUrls,1);
  assert.ok(!rules.some(r => r.condition.urlFilter?.includes('bad.test/')));
});

test('세션 예외는 URL과 탭 번호로 제한되며 URL은 정확히 일치해야 한다', () => {
  const c = sessionAllowCondition('https://bad.test/a',17);
  assert.deepEqual(c.tabIds,[17]);
  assert.equal(c.urlFilter,'|https://bad.test/a|');
  assert.throws(() => sessionAllowCondition('javascript:alert(1)',17), /올바르지/);
  assert.throws(() => sessionAllowCondition('http://x/',-1), /올바르지/);
});
