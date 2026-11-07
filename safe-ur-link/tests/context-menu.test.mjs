import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CONTEXT_MENUS, SELECTED_URL_MENU_ID,
  targetFromContext, isSelectedUrl, resultPageUrl, registerContextMenu
} from '../core/context-menu.js';

const runtime = { getURL: path => `chrome-extension://testid/${path}`, lastError: null };

test('드래그한 URL이 있으면 하이퍼링크 주소와 페이지 URL을 모두 무시한다', () => {
  const selected = targetFromContext({
    menuItemId: SELECTED_URL_MENU_ID,
    selectionText: ' https://selected.example/file?a=1&b=2 ',
    linkUrl: 'https://different.example/redirect',
    pageUrl: 'https://page.example/'
  });
  assert.deepEqual(selected, { url: 'https://selected.example/file?a=1&b=2', mode: 'selection' });
});

test('해당 메뉴의 값이 없으면 다른 필드로 대체하지 않는다', () => {
  assert.equal(targetFromContext({ menuItemId: SELECTED_URL_MENU_ID, linkUrl: 'https://wrong.example', pageUrl: 'https://page.example' }), null);
  assert.equal(targetFromContext({ menuItemId: 'check-link', selectionText: 'https://wrong.example', linkUrl: 'https://old.example' }), null);
  assert.equal(targetFromContext({ menuItemId: 'check', selectionText: 'https://old.example/' }), null);
  assert.equal(targetFromContext(null), null);
});

test('일반 문구를 임의 도메인으로 인식하지 않고 정확히 URL인 텍스트만 허용한다', () => {
  for (const value of ['https://example.com/path?q=2', 'example.com/path', 'localhost:3000', 'http://dev-host/', '192.168.0.1', '[::1]:8080']) {
    assert.equal(isSelectedUrl(value), true, `허용: ${value}`);
  }
  for (const value of ['여기를 클릭', 'login', 'https://first.example https://second.example', 'javascript:alert(1)', 'chrome://settings', '', 'ftp://example.org']) {
    assert.equal(isSelectedUrl(value), false, `거부: ${value}`);
  }
});

test('내부 결과 탭 URL 인코딩 시 선택 대상과 유형이 그대로 보존된다', () => {
  const value = 'https://a.test/경로?a=1&b=<test>#부분';
  const result = resultPageUrl(runtime, { url: value, mode: 'selection' });
  const u = new URL(result);
  assert.equal(u.pathname, '/pages/result/result.html');
  assert.equal(u.searchParams.get('url'), value);
  assert.equal(u.searchParams.get('mode'), 'selection');
  assert.equal(u.hostname, 'testid');
});

function contextApi() {
  const calls = [];
  const api = {
    runtime: { lastError: null },
    contextMenus: {
      removeAll(cb) { calls.push('removeAll'); cb(); },
      create(props, cb) { calls.push({ ...props }); cb(); }
    }
  };
  return { api, calls };
}

test('설치/시작마다 기존 메뉴 정리 후 선택 URL 메뉴 하나만 등록한다', async () => {
  const { api, calls } = contextApi();
  await registerContextMenu(api);
  await registerContextMenu(api);
  assert.equal(calls.length, 4);
  assert.equal(calls[0], 'removeAll');
  assert.deepEqual(calls[1], CONTEXT_MENUS[0]);
  assert.equal(calls[2], 'removeAll');
  assert.deepEqual(calls[3], CONTEXT_MENUS[0]);
  assert.equal(CONTEXT_MENUS.length, 1);
  assert.deepEqual(CONTEXT_MENUS[0].contexts, ['selection']);
});

test('우클릭 메뉴 등록 실패는 오류로 보고한다', async () => {
  const { api } = contextApi();
  api.contextMenus.create = (_, callback) => {
    api.runtime.lastError = { message: 'duplicate id' };
    callback();
  };
  await assert.rejects(registerContextMenu(api), /등록 실패 .*duplicate id/);
});
