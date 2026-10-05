import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import test from 'node:test';

const source = readFileSync(new URL('../../src/background.js', import.meta.url), 'utf8')
  .replace('import { ApplePasswords, State } from "./protocol.js";', '');

const tick = () => new Promise(resolve => setImmediate(resolve));

function setup() {
  let listener, stateListener;
  let now = 1000;
  const timers = new Map();
  const sends = [], queries = [], calls = [], saves = [];
  let onDelivery = () => {};
  let delivery = { filled: true };
  const hooks = { lookup: async () => {}, beforeSend: async () => {} };
  const frames = new Map();
  const id = 'audit-extension';
  const target = { tabId: 7, frameId: 0, documentId: 'doc-a', url: 'https://account.example/login', origin: 'https://account.example' };
  frames.set(target.documentId, target);
  let active = { id: 7, url: target.url };
  const code = { source: 'totp', username: 'dummy', domain: 'account.example', code: '123456' };
  const setState = (state) => { client.ready = state === 'unlocked'; client.state = state; stateListener(state); };
  const client = {
    state: 'unlocked', ready: true, canFillOneTimeCodes: true,
    onStateChange(fn) { stateListener = fn; }, onOneTimeCodeAvailable() {},
    async connect() { client.state = 'needs_pin'; },
    async getLoginNamesForURL(tabId, url) { calls.push('getLoginNamesForURL'); await hooks.lookup(); return [{ username: 'dummy' }]; },
    async getPasswordForLoginName(tabId, url, login) {
      calls.push('getPasswordForLoginName');
      queries.push({ tabId, url }); return { username: login.username, password: 'DUMMY_ONLY' };
    },
    async getOneTimeCodes() { calls.push('getOneTimeCodes'); return { entries: [code], requiresAuth: false }; },
    async readOneTimeCode() { calls.push('readOneTimeCode'); return [code]; },
    // stands in for the native queue: shouldSend is asked last, right before the helper would see the password
    async saveLogin(tabId, url, username, password, options = {}) {
      calls.push('saveLogin');
      await hooks.beforeSend();
      if (options.shouldSend && !options.shouldSend()) return false;
      saves.push({ url, username, password });
      return true;
    },
    async verifyPin() { setState('unlocked'); },
    disconnect() { setState('disconnected'); },
  };
  const event = () => ({ addListener() {} });
  const chrome = {
    runtime: { id, getURL: p => `chrome-extension://${id}/${p}`,
      onMessage: { addListener(fn) { listener = fn; } }, onInstalled: event(), onStartup: event(),
      sendMessage: async () => ({}), getPlatformInfo() {},
    },
    action: { async openPopup() {}, async setIcon() {} },
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
        if (typeof options === 'function') options(delivery);
        return delivery;
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
  return { target, client, code, frames, sends, queries, calls, saves, hooks, context,
    onDelivery(fn) { onDelivery = fn; },
    setDelivery(result) { delivery = result; },
    send: (msg, from = ui) => new Promise(resolve => listener(msg, from, resolve)), sender,
    navigate(t) { frames.clear(); frames.set(t.documentId, t); active = { id: t.tabId, url: t.url }; },
    lock() { setState('needs_pin'); },
    timerCount: () => timers.size,
    pending: () => vm.runInContext('pendingSaves.size ?? pendingSaves.length', context),
    advance(ms) { now += ms; for (const [key, timer] of [...timers]) if (timer.at <= now) { timers.delete(key); timer.fn(); } },
  };
}

test('refresh handlers never read or deliver secrets for an HTTP page', async () => {
  const e = setup();
  await e.send({ type: 'fillOnPage', target: e.target, loginName: { username: 'dummy' } });
  const list = await e.send({ type: 'getOneTimeCodes', target: e.target });
  const http = { ...e.target, documentId: 'http-doc', url: 'http://account.example/login', origin: 'http://account.example' };
  e.navigate(http);
  e.calls.length = 0;
  e.sends.length = 0;

  // what the popup refresh does now: clear, re-resolve the page, reload lists, then any fill the user picks
  assert.equal((await e.send({ type: 'clearCache' })).ok, true);
  for (const msg of [
    { type: 'getPageTarget' },
    { type: 'getLogins', target: http },
    { type: 'getOneTimeCodes', target: http },
    { type: 'fillOnPage', target: http, loginName: { username: 'dummy' } },
    { type: 'fillOneTimeCode', target: http, id: list.rows[0].id },
    // the HTTPS target the popup held before the downgrade
    { type: 'getLogins', target: e.target },
    { type: 'fillOnPage', target: e.target, loginName: { username: 'dummy' } },
  ]) {
    assert.equal((await e.send(msg)).ok, false, msg.type);
  }
  for (const type of ['inlineLogins', 'inlineFill', 'inlineOneTimeCodes', 'inlineFillOneTimeCode']) {
    const response = await e.send({ type, loginName: { username: 'dummy' }, id: list.rows[0].id }, e.sender(http));
    assert.equal(response.ok, false, type);
  }
  // the removed refresh-and-refill endpoint stays gone
  const legacy = await e.send({ type: 'refreshAndRefill' });
  assert.equal(legacy.ok, false);
  assert.notEqual(legacy.refilled, true);

  assert.deepEqual(e.calls, []);
  assert.equal(e.sends.length, 0);
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

test('a filled OTP is never returned to the popup', async () => {
  const e = setup();
  const list = await e.send({ type: 'getOneTimeCodes', target: e.target });
  const r = await e.send({ type: 'fillOneTimeCode', target: e.target, id: list.rows[0].id });
  assert.equal(r.filled, true);
  assert.equal(JSON.stringify(r).includes(e.code.code), false);
});

test('a page with no code field answers no, so only the popup can show the code', async () => {
  const e = setup();
  e.setDelivery({ ok: true, filled: false, error: 'no code field' });
  const list = await e.send({ type: 'getOneTimeCodes', target: e.target });
  const r = await e.send({ type: 'fillOneTimeCode', target: e.target, id: list.rows[0].id });
  assert.equal(r.ok, true);
  assert.equal(r.filled, false);
  assert.equal(r.code, e.code.code);

  // the page's own inline request never gets the code back
  const inline = await e.send({ type: 'inlineOneTimeCodes' }, e.sender(e.target));
  const reply = await e.send({ type: 'inlineFillOneTimeCode', id: inline.rows[0].id }, e.sender(e.target));
  assert.equal(reply.filled, false);
  assert.equal(JSON.stringify(reply).includes(e.code.code), false);
});

const deferredSave = { type: 'resolveSave', username: 'dummy', password: 'DUMMY_ONLY', newPwCtx: true };

test('a new-password save made while locked is sent once after the user unlocks', async () => {
  const e = setup();
  e.lock();
  assert.equal((await e.send(deferredSave, e.sender(e.target))).locked, true);
  assert.equal(e.pending(), 1);
  assert.equal(e.saves.length, 0);

  assert.equal((await e.send({ type: 'verifyPin', pin: '000000' })).ok, true);
  await tick();
  assert.deepEqual(e.saves.map(s => s.password), ['DUMMY_ONLY']);
  assert.equal(e.pending(), 0);
  assert.equal(e.timerCount(), 0);
});

test('Lock drops deferred saves and their timers, so a later unlock saves nothing', async () => {
  const e = setup();
  e.lock();
  await e.send(deferredSave, e.sender(e.target));
  assert.equal(e.pending(), 1);
  assert.equal(e.timerCount(), 1);

  await e.send({ type: 'disconnect' });
  assert.equal(e.pending(), 0);
  assert.equal(e.timerCount(), 0);

  await e.send({ type: 'verifyPin', pin: '000000' });
  await tick();
  assert.equal(e.calls.includes('saveLogin'), false);
  assert.equal(e.saves.length, 0);
});

test('deferred saves expire, including while the unlock lookup is still running', async () => {
  const e = setup();
  e.lock();
  await e.send(deferredSave, e.sender(e.target));
  e.advance(120_001);
  assert.equal(e.pending(), 0);

  await e.send(deferredSave, e.sender(e.target));
  e.hooks.lookup = async () => e.advance(120_001);
  await e.send({ type: 'verifyPin', pin: '000000' });
  await tick();
  assert.equal(e.calls.includes('saveLogin'), false);
  assert.equal(e.saves.length, 0);
});

test('Lock while a deferred save waits in the native queue stops it before the helper', async () => {
  const e = setup();
  e.lock();
  await e.send(deferredSave, e.sender(e.target));
  e.hooks.beforeSend = () => e.send({ type: 'disconnect' });
  await e.send({ type: 'verifyPin', pin: '000000' });
  await tick();
  assert.equal(e.calls.includes('saveLogin'), true);
  assert.equal(e.saves.length, 0);
  assert.equal(e.pending(), 0);
});
