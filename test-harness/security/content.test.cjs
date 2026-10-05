// Offline security reproductions. Loads the installed content source unchanged
// into a VM with a minimal DOM model. No browser, vault, network, or real secrets.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const path = require('node:path');
const test = require('node:test');
const source = fs.readFileSync(path.join(__dirname, '../../src/content.js'), 'utf8');
class FakeElement {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = []; this.attrs = {}; this.handlers = {};
    this.style = { setProperty(k, v) { this[k] = v; } };
    this.isConnected = true; this.offsetParent = {}; this.offsetHeight = 100;
    this.name = ''; this.id = ''; this.type = 'text'; this.form = null;
    this._value = ''; this.textContent = ''; this.inputMode = '';
    this.computed = { display: 'block', visibility: 'visible', opacity: '1', position: 'static' };
  }
  setAttribute(k, v) { this.attrs[k] = v; }
  getAttribute(k) { return this.attrs[k] ?? null; }
  removeAttribute(k) { delete this.attrs[k]; }
  appendChild(child) { this.children.push(child); child.parent = this; return child; }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(x => x !== this); this.isConnected = false; }
  contains(el) { return this === el || this.children.some(child => child.contains(el)); }
  addEventListener(type, fn) { (this.handlers[type] ??= []).push(fn); }
  dispatchEvent(event) { for (const fn of this.handlers[event.type] ?? []) fn(event); return true; }
  focus() {}
  getBoundingClientRect() { return { left: 20, top: 20, right: 240, bottom: 50, width: 220, height: 30 }; }
  getRootNode() { return this.ownerDocument; }
  querySelectorAll(selector) {
    return this.children.flatMap(child => [child, ...child.querySelectorAll('*')]).filter(child =>
      selector === '*' || (selector === 'input' && child instanceof FakeInput) ||
      (selector === 'input[type="password"]' && child instanceof FakeInput && child.type === 'password'));
  }
  compareDocumentPosition() { return 4; }
  scrollIntoView() {}
  closest() { return null; }
}
class FakeInput extends FakeElement {
  constructor() { super('input'); }
  get value() { return this._value; }
  set value(value) { this._value = value; }
}
class FakeEvent {
  constructor(type, options = {}) { Object.assign(this, options); this.type = type; this.isTrusted = false; }
  preventDefault() {}
  stopPropagation() {}
  stopImmediatePropagation() {}
}

const defaultReply = () => ({ ok: true, state: 'needs_pin', logins: [] });

function environment(url, topUrl = url, reply = defaultReply) {
  const messages = [], receivers = [];
  const document = new FakeElement('document');
  document.createElement = tag => {
    const element = tag === 'input' ? new FakeInput() : new FakeElement(tag);
    element.ownerDocument = document; return element;
  };
  document.head = document.createElement('head');
  document.body = document.createElement('body');
  document.documentElement = document.createElement('html');
  document.append(document.head, document.body);
  document.activeElement = null;
  const location = new URL(url);
  const window = { location, innerWidth: 1200, innerHeight: 900, scrollX: 0, scrollY: 0, addEventListener() {} };
  window.top = topUrl === url ? window : { location: new URL(topUrl) };
  const chrome = { runtime: {
    id: 'test-extension-id', getURL: path => `chrome-extension://test-extension-id/${path}`,
    onMessage: { addListener(fn) { receivers.push(fn); } },
    sendMessage(message) { messages.push(message); return Promise.resolve(reply(message)); },
  } };
  const context = vm.createContext({ document, location, window, chrome, console: { log() {}, debug() {} },
    HTMLInputElement: FakeInput, HTMLTextAreaElement: FakeElement, Element: FakeElement,
    Event: FakeEvent, KeyboardEvent: FakeEvent, Node: { DOCUMENT_POSITION_FOLLOWING: 4 },
    getComputedStyle: element => element.computed, setTimeout() {}, clearTimeout() {},
  });
  vm.runInContext(source, context, { filename: 'installed-content.js' });
  return { context, document, messages, receivers, chrome };
}


test('inline unlock opens protected popup without adding a PIN input to the page', async () => {
  const env = environment('https://account.example/login');
  const anchor = env.document.createElement('input');
  env.document.body.appendChild(anchor);
  env.context.dummyField = anchor;
  await vm.runInContext('buildLockedSuggestion(dummyField)', env.context);
  const box = env.document.body.children.find(el => el.attrs['data-open-passwords'] === 'suggestions');
  assert.equal(box.querySelectorAll('input').length, 0);
  assert(env.messages.some(msg => msg.type === 'openPopup'));
  assert(!env.messages.some(msg => ['verifyPin', 'requestChallenge'].includes(msg.type)));
});

for (const [name, url, expectedOrigin, expectedUrl, accepted] of [
  ['correct origin and page', 'https://account.example/login', 'https://account.example', 'https://account.example/login', true],
  ['HTTP downgrade', 'http://account.example/login', 'https://account.example', 'https://account.example/login', false],
  ['different port', 'https://account.example:8443/login', 'https://account.example', 'https://account.example/login', false],
  ['same-document path change', 'https://account.example/other', 'https://account.example', 'https://account.example/login', false],
  ['missing expected origin', 'https://account.example/login', undefined, undefined, false],
]) {
  test(`credential receiver: ${name}`, () => {
    const env = environment(url);
    const password = env.document.createElement('input'); password.type = 'password';
    env.document.body.appendChild(password);
    let reply;
    env.receivers[0]({ type: 'fill', expectedOrigin, expectedUrl, password: 'DUMMY_ONLY' },
      { id: env.chrome.runtime.id }, result => { reply = result; });
    assert.equal(reply.filled, accepted);
    assert.equal(password.value, accepted ? 'DUMMY_ONLY' : '');
  });
}

const trusted = (type, options) => Object.assign(new FakeEvent(type, options), { isTrusted: true });

// an open inline box with two dummy logins, anchored to a focused field
async function openLoginBox() {
  const env = environment('https://account.example/login', undefined, msg =>
    msg.type === 'inlineLogins' ? { ok: true, locked: false, logins: [{ username: 'dummy-a' }, { username: 'dummy-b' }] } : { ok: true });
  const field = env.document.createElement('input');
  env.document.body.appendChild(field);
  env.document.activeElement = field;
  env.context.dummyField = field;
  await vm.runInContext('buildOfferSuggestion(dummyField)', env.context);
  const box = env.document.body.children.find(el => el.attrs['data-open-passwords'] === 'suggestions');
  const rows = box.children.filter(el => el.attrs.role === 'option');
  const enter = () => env.document.dispatchEvent(trusted('keydown', { key: 'Enter', target: field }));
  const fills = () => env.messages.filter(msg => msg.type === 'inlineFill').map(msg => msg.loginName.username);
  return { env, field, rows, enter, fills };
}

test('a page-dispatched hover cannot choose the row a real Enter activates', async () => {
  const { rows, enter, fills } = await openLoginBox();
  assert.equal(rows.length, 2);
  rows[1].dispatchEvent(new FakeEvent('mouseenter'));
  enter();
  assert.deepEqual(fills(), []);
});

test('a real hover or arrow key still selects the row Enter fills', async () => {
  let box = await openLoginBox();
  box.rows[1].dispatchEvent(trusted('mouseenter'));
  box.enter();
  assert.deepEqual(box.fills(), ['dummy-b']);

  box = await openLoginBox();
  box.env.document.dispatchEvent(trusted('keydown', { key: 'ArrowDown', target: box.field }));
  box.enter();
  assert.deepEqual(box.fills(), ['dummy-a']);
});

test('Enter never activates a selected row that is no longer visible', async () => {
  const { env, field, rows, enter, fills } = await openLoginBox();
  env.document.dispatchEvent(trusted('keydown', { key: 'ArrowDown', target: field }));
  rows[0].computed.opacity = '0';
  enter();
  assert.deepEqual(fills(), []);
});

test('a code fill on a page without a code field gets an explicit no', () => {
  const env = environment('https://account.example/verify');
  let reply;
  const kept = env.receivers[1]({ type: 'fillOtp', code: '000000', expectedOrigin: 'https://account.example', expectedUrl: 'https://account.example/verify' },
    { id: env.chrome.runtime.id }, result => { reply = result; });
  assert.equal(kept, true);
  assert.equal(reply.ok, true);
  assert.equal(reply.filled, false);

  const otp = env.document.createElement('input');
  otp.setAttribute('autocomplete', 'one-time-code');
  env.document.body.appendChild(otp);
  env.receivers[1]({ type: 'fillOtp', code: '000000', expectedOrigin: 'https://account.example', expectedUrl: 'https://account.example/verify' },
    { id: env.chrome.runtime.id }, result => { reply = result; });
  assert.equal(reply.filled, true);
  assert.equal(otp.value, '000000');
});
