import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { validateFeed } from '../core/remote-feed.js';
import { normalizeUrl } from '../core/common.js';
import { evaluateUrl } from '../core/scan.js';

const feed = validateFeed(JSON.parse(await readFile(new URL('../public/signatures.json', import.meta.url), 'utf8')));
const find = raw => feed.records.filter(record => record.url === normalizeUrl(raw));

test('ZIP 시그니처 형식을 변경하지 않고 정확히 일치하는 데모 URL을 탐지한다', () => {
  for (const url of ['https://phishing.test/login', 'http://malware.test/demo']) {
    const hit = find(url);
    assert.equal(hit.length, 1);
    const result = evaluateUrl(url, hit);
    assert.equal(result.verdict, 'Malicious');
    assert.deepEqual(result.sources, ['Demo']);
    assert.ok(result.externalScore >= 30);
  }
});

test('확장 프로그램과 같은 URL 정규화로 fragment 제외·대소문자 호스트 일치', () => {
  const url = 'HTTPS://PHISHING.TEST/login#what';
  assert.equal(normalizeUrl(url), 'https://phishing.test/login');
  assert.equal(evaluateUrl(url, find(url)).verdict, 'Malicious');
});

test('정확한 URL 시그니처만 매칭하며 인접 URL을 오탐하지 않는다', () => {
  assert.equal(evaluateUrl('https://phishing.test/login2', find('https://phishing.test/login2')).verdict, 'No Threat Detected');
  assert.equal(evaluateUrl('https://example.com/', find('https://example.com/')).verdict, 'No Threat Detected');
});

test('외부 DB 출처와 메타데이터 점수를 합산해 같은 점수 정책을 따른다', () => {
  const url = 'https://record.invalid/';
  const records = [
    { url, source: 'URLhaus', meta: { verified: true, online: true, confidence: 80 } },
    { url, source: 'PhishTank', meta: { valid: true } }
  ];
  const result = evaluateUrl(url, records);
  assert.equal(result.externalScore, 48); // 30 기본 + 10 교차 + 8 메타데이터
  assert.equal(result.heuristicScore, 0);
  assert.equal(result.score, 48);
  assert.equal(result.verdict, 'Malicious');
});

test('과거 등록 이력만 발견되면 자동 악성 확정 대신 Suspicious를 반환한다', () => {
  const url = 'https://old.invalid/path';
  const result = evaluateUrl(url, [{ url, source: 'URLhaus', meta: { active: false } }]);
  assert.equal(result.verdict, 'Suspicious');
  assert.equal(result.historyOnly, true);
  assert.equal(result.externalScore, 30);
});

test('위험 구조가 감지되어도 DB 미등록 URL은 악성으로 확정하지 않는다', () => {
  const url = 'http://guest@one.two.three.four.xn--bcher-kva.invalid/login/' + 'a'.repeat(130) + '?password=verify%20%20%20%20%20';
  const result = evaluateUrl(url, []);
  assert.equal(result.verdict, 'Suspicious');
  assert.equal(result.externalScore, 0);
  assert.ok(result.heuristicScore >= 30);
});

test('사용자 지정 허용·차단 목록 우선순위를 기존 확장 프로그램과 동일하게 유지한다', () => {
  const url = 'https://blocked.invalid/';
  const records = [{ url, source: 'URLhaus', meta: {} }];
  const allow = evaluateUrl(url, records, { allow: ['blocked.invalid'], block: ['blocked.invalid'] });
  const block = evaluateUrl(url, records, { block: ['blocked.invalid'] });
  assert.equal(allow.verdict, 'No Threat Detected');
  assert.equal(block.verdict, 'Malicious');
  assert.equal(block.score, 100);
});

test('유효하지 않은 URL은 검사 중 오류 결과로 처리된다', () => {
  assert.match(evaluateUrl('http://[]').error, /http\/https/);
});
