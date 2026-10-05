import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import test from 'node:test';

const source = readFileSync(new URL('../../src/background.js', import.meta.url), 'utf8')
  .replace('import { ApplePasswords, State } from "./protocol.js";', '');

function setup() {
  let listener, stateListener;
  let now = 1000;
  const timers = new Map();
  const sends = [], queries = [];
  let onDelivery = () => {};
  const frames = new Map();
  const id = 'audit-extension';
  const target = { tabId: 7, frameId: 0, documentId: 'doc-a', url: 'https://account.example/login', origin: 'https://account.example' };
  frames.set(target.documentId, target);
  let active = { id: 7, url: target.url };
  const code = { source: 'totp', username: 'dummy', domain: 'account.example', code: '123456' };
  const client = {
    state: 'unlocked', ready: true, canFillOneTimeCodes: true,
    onStateChange(fn) { stateListener = fn; }, onOneTimeCodeAvailable() {},
    async getLoginNamesForURL() { return [{ username: 'dummy' }]; },
    async getPasswordForLoginName(tabId, url, login) {
      queries.push({ tabId, url }); return { username: login.username, password: 'DUMMY_ONLY' };
    },
    async getOneTimeCodes() { return { entries: [code], requiresAuth: false }; },
    async readOneTimeCode() { return [code]; },
  };
  const event = () => ({ addListener() {} });
  const chrome = {
    runtime: { id, getURL: p => `chrome-extension://${id}/${p}`,
      onMessage: { addListener(fn) { listener = fn; } }, onInstalled: event(), onStartup: event(),
      sendMessage: async () => ({}), getPlatformInfo() {},
    },
    action: { async openPopup() {} },
    alarms: { create() {}, onAlarm: event() }, commands: { onCommand: event() },
    tabs: {
      query: async () => [active], onRemoved: event(),
      async sendMessage(tabId, msg, options) {
        if (msg.type === 'getFrameContext') {
          const frame = options.documentId ? frames.get(options.documentId) : [...frames.values()].find(f => f.frameId === options.frameId);
          if (!frame) throw new Error('document gone');
          return { ok: true, target: { ...frame } };
        }
        sends.push({ tabId, msg, options });
        await onDelivery();
        if (typeof options === 'function') options({ filled: true });
        return { filled: true };
      },
    },
  };
  const context = vm.createContext({ chrome, ApplePasswords: function () { return client; },
    State: { Unlocked: 'unlocked', NeedsPin: 'needs_pin', Disconnected: 'disconnected' },
    URL, crypto: webcrypto, console, Date: { now: () => now },
    setTimeout(fn, ms) { const key = {}; timers.set(key, { fn, at: now + ms }); return key; },
    clearTimeout(key) { timers.delete(key); },
  });
  vm.runInContext(source, context);
  const ui = { id, url: `chrome-extension://${id}/src/popup.html` };
  const sender = t => ({ id, tab: active, frameId: t.frameId, documentId: t.documentId, url: t.url, origin: t.origin });
  return { target, client, code, frames, sends, queries, context,
    onDelivery(fn) { onDelivery = fn; },
    send: (msg, from = ui) => new Promise(resolve => listener(msg, from, resolve)), sender,
    navigate(t) { frames.clear(); frames.set(t.documentId, t); active = { id: t.tabId, url: t.url }; },
    lock() { client.ready = false; client.state = 'needs_pin'; stateListener('needs_pin'); },
    advance(ms) { now += ms; for (const [key, timer] of [...timers]) if (timer.at <= now) { timers.delete(key); timer.fn(); } },
  };
}

test('refresh never fetches or fills credentials on an HTTP navigation', async () => {
  const e = setup();
  await e.send({ type: 'fillOnPage', target: e.target, loginName: { username: 'dummy' } });
  e.navigate({ ...e.target, documentId: 'http-doc', url: 'http://account.example/login', origin: 'http://account.example' });
  const before = e.queries.length;
  const response = await e.send({ type: 'refreshAndRefill' });
  assert.notEqual(response.refilled, true);
  assert.equal(e.queries.length, before);
});

test('content scripts cannot submit pairing PINs or request challenges', async () => {
  const e = setup();
  for (const type of ['verifyPin', 'requestChallenge']) {
    const response = await e.send({ type, pin: '000000' }, e.sender(e.target));
    assert.equal(response.error, 'forbidden');
  }
});

test('OTP from an old page is rejected before a secret is read or sent', async () => {
  const e = setup();
  const list = await e.send({ type: 'getOneTimeCodes', target: e.target });
  const next = { ...e.target, documentId: 'doc-b', url: 'https://other.example/verify', origin: 'https://other.example' };
  e.navigate(next);
  const response = await e.send({ type: 'fillOneTimeCode', target: next, id: list.rows[0].id });
  assert.equal(response.ok, false);
  assert.equal(e.sends.length, 0);
});

test('password delivery is bound to document and complete origin', async () => {
  const e = setup();
  const r = await e.send({ type: 'inlineFill', loginName: { username: 'dummy' } }, e.sender(e.target));
  assert.equal(r.filled, true);
  assert.equal(e.sends[0].options.documentId, e.target.documentId);
  assert.equal(e.sends[0].msg.expectedOrigin, e.target.origin);
  assert.equal(e.sends[0].msg.expectedUrl, e.target.url);
});

test('navigation during native authorization never sends the returned password', async () => {
  const e = setup();
  e.client.getPasswordForLoginName = async () => {
    e.navigate({ ...e.target, documentId: 'replacement' });
    return { username: 'dummy', password: 'DUMMY_ONLY' };
  };
  assert.equal((await e.send({ type: 'fillOnPage', target: e.target, loginName: { username: 'dummy' } })).ok, false);
  assert.equal(e.sends.length, 0);
});

test('locking while a native read is pending rejects its result', async () => {
  const e = setup();
  e.client.getPasswordForLoginName = async () => { e.lock(); return { username: 'dummy', password: 'DUMMY_ONLY' }; };
  assert.equal((await e.send({ type: 'fillOnPage', target: e.target, loginName: { username: 'dummy' } })).ok, false);
  assert.equal(e.sends.length, 0);
});

test('password cache actively removes expired plaintext without another lookup', async () => {
  const e = setup();
  await e.send({ type: 'inlineFill', loginName: { username: 'dummy' } }, e.sender(e.target));
  assert.equal(vm.runInContext('pwCache.size', e.context), 1);
  e.advance(120001);
  assert.equal(vm.runInContext('pwCache.size', e.context), 0);
});

test('lock during delivery cannot repopulate the plaintext cache', async () => {
  const e = setup();
  e.onDelivery(() => e.lock());
  const response = await e.send({ type: 'fillOnPage', target: e.target, loginName: { username: 'dummy' } });
  assert.equal(response.ok, false);
  assert.equal(vm.runInContext('pwCache.size', e.context), 0);
});

test('lock during OTP delivery cannot return the code to the popup', async () => {
  const e = setup();
  const list = await e.send({ type: 'getOneTimeCodes', target: e.target });
  e.onDelivery(() => e.lock());
  const response = await e.send({ type: 'fillOneTimeCode', target: e.target, id: list.rows[0].id });
  assert.equal(response.ok, false);
  assert.equal(response.code, undefined);
});

test('valid same-document OTP fill works, with no account fallback', async () => {
  const e = setup();
  let list = await e.send({ type: 'getOneTimeCodes', target: e.target });
  let r = await e.send({ type: 'fillOneTimeCode', target: e.target, id: list.rows[0].id });
  assert.equal(r.filled, true);
  assert.equal(e.sends.at(-1).options.documentId, e.target.documentId);
  e.sends.length = 0;
  list = await e.send({ type: 'getOneTimeCodes', target: e.target });
  e.client.readOneTimeCode = async () => [{ ...e.code, username: 'another-user' }];
  r = await e.send({ type: 'fillOneTimeCode', target: e.target, id: list.rows[0].id });
  assert.equal(r.ok, false);
  assert.equal(e.sends.length, 0);
});
