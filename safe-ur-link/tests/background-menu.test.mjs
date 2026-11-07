import test from 'node:test';
import assert from 'node:assert/strict';

// Service Worker 이벤트만 모의하며 외부 피드나 DB는 요청하지 않는다.
const events = {};
const opened = [];
const register = name => ({ addListener(fn) { events[name] = fn; } });
globalThis.chrome = {
  runtime: {
    getURL: path => `chrome-extension://test-ext/${path}`,
    onInstalled: register('installed'),
    onStartup: register('startup'),
    onMessage: register('message')
  },
  alarms: { onAlarm: register('alarm') },
  contextMenus: { onClicked: register('clicked') },
  tabs: { async create(tab) { opened.push(tab); return { id: opened.length }; } }
};
await import('../background/background.js');

const settled = () => new Promise(resolve => setImmediate(resolve));

test('MV3 워커에서 우클릭 핸들러가 등록된다', () => {
  assert.equal(typeof events.clicked, 'function');
  assert.equal(typeof events.installed, 'function');
  assert.equal(typeof events.startup, 'function');
});

test('선택 URL 검사는 linkUrl과 pageUrl이 있더라도 드래그한 텍스트만 전달한다', async () => {
  events.clicked({
    menuItemId: 'check-selection',
    selectionText: ' https://selected.example/path?a=1&b=2 ',
    linkUrl: 'https://wrong-link.example/',
    pageUrl: 'https://wrong-page.example/'
  });
  await settled();
  const openedUrl = new URL(opened.at(-1).url);
  assert.equal(openedUrl.protocol, 'chrome-extension:');
  assert.equal(openedUrl.pathname, '/pages/result/result.html');
  assert.equal(openedUrl.searchParams.get('url'), 'https://selected.example/path?a=1&b=2');
  assert.equal(openedUrl.searchParams.get('mode'), 'selection');
});

test('다른 메뉴 또는 선택 텍스트가 없는 경우 다른 URL로 대체하지 않는다', async () => {
  const before = opened.length;
  events.clicked({ menuItemId: 'other', selectionText: 'https://some.example' });
  events.clicked({ menuItemId: 'check-selection', linkUrl: 'https://some.example' });
  events.clicked({ menuItemId: 'check-link', selectionText: 'https://some.example', linkUrl: 'https://true-href.example' });
  await settled();
  assert.equal(opened.length, before);
});
