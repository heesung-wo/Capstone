import test from 'node:test';
import assert from 'node:assert/strict';

const listeners = new Map();
const documentListeners = {};
const elements = {};
const registered = (id, event, callback) => listeners.set(`${id}:${event}`, callback);
const input = {
  tagName: 'INPUT', value: 'https://example.com/check?x=1', selectionStart: 5, selectionEnd: 5,
  focus() { document.activeElement = this; },
  select() { this.selectionStart = 0; this.selectionEnd = this.value.length; },
  addEventListener(name, handler) { registered('u', name, handler); },
};
for (const id of ['go', 'tab', 'opt', 'st', 'out']) {
  elements[id] = {
    tagName: id === 'go' || id === 'tab' ? 'BUTTON' : 'DIV',
    disabled: false, textContent: '', innerHTML: '',
    addEventListener(name, handler) { registered(id, name, handler); },
    click() { const handler = listeners.get(`${id}:click`); if (handler) return handler(); },
  };
}
elements.u = input;
globalThis.document = {
  activeElement: null,
  getElementById: id => elements[id],
  addEventListener(name, handler) { documentListeners[name] = handler; },
};
const calls = [];
let shouldThrow = false;
globalThis.chrome = {
  runtime: {
    sendMessage: async message => {
      calls.push(message);
      if (message.type === 'status') return { counts: {} };
      if (shouldThrow) throw new Error('simulated failure');
      return { verdict: 'No Threat Detected', score: 0, reasons: [], sources: [] };
    },
    openOptionsPage() {},
  },
  tabs: { query: async () => [{ url: 'https://example.org/' }] },
};
await import('../pages/popup/popup.js');
const keyboard = (key, extras = {}) => {
  let prevented = false;
  const event = {
    key, target: input, ctrlKey: false, metaKey: false, altKey: false, shiftKey: false,
    isComposing: false, repeat: false,
    preventDefault() { prevented = true; },
    ...extras,
  };
  listeners.get('u:keydown')(event);
  documentListeners.keydown(event);
  return prevented;
};

test('다른 버튼에 포커스가 있을 때도 Ctrl+A가 URL 전체를 선택한다', () => {
  document.activeElement = elements.go;
  input.selectionStart = input.selectionEnd = 5;
  let prevented = false;
  documentListeners.keydown({ key: 'a', target: elements.go, ctrlKey: true, metaKey: false, altKey: false, shiftKey: false,
    preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(document.activeElement, input);
  assert.equal(input.selectionStart, 0);
  assert.equal(input.selectionEnd, input.value.length);
});

test('입력창에 포커스된 Ctrl+A, Cmd+A는 브라우저의 기본 선택 기능을 사용한다', () => {
  assert.equal(keyboard('a', { ctrlKey: true }), false);
  assert.equal(keyboard('a', { metaKey: true }), false);
});

test('Backspace, Delete, Space, 화살표, Home/End, 일반 입력은 기본 키보드 동작을 차단하지 않는다', () => {
  for (const key of ['Backspace', 'Delete', ' ', 'ArrowLeft', 'ArrowRight', 'Home', 'End', 'a', '0']) {
    assert.equal(keyboard(key), false, `${key} should not be prevented`);
  }
});

test('Ctrl+V/C/X/Z/Y 및 Shift 입력도 브라우저 기본 동작을 사용한다', () => {
  for (const key of ['v', 'c', 'x', 'z', 'y']) assert.equal(keyboard(key, { ctrlKey: true }), false);
  assert.equal(keyboard('a', { shiftKey: true }), false);
  assert.equal(listeners.has('u:paste'), false, '붙여넣기를 강제로 가로채지 않는다');
});

test('Enter는 검사 버튼을 실행하며 한글 조합 중에는 검사하지 않는다', async () => {
  const before = calls.length;
  assert.equal(keyboard('Enter', { isComposing: true }), false);
  assert.equal(calls.length, before);
  assert.equal(keyboard('Enter'), true);
  assert.equal(calls.length, before + 1);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(document.activeElement, input);
  assert.equal(elements.go.disabled, false);
  assert.equal(elements.tab.disabled, false);
});

test('검사 실패 후에도 입력창의 포커스와 버튼 사용 가능 상태를 복구한다', async () => {
  shouldThrow = true;
  document.activeElement = elements.go;
  const origConsole = console.error;
  console.error = () => {};
  try {
    elements.go.click();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(document.activeElement, input);
    assert.equal(elements.go.disabled, false);
    assert.equal(elements.tab.disabled, false);
    assert.match(elements.out.textContent, /오류/);
  } finally {
    shouldThrow = false;
    console.error = origConsole;
  }
});
