// Offline stand-in for Apple's native helper. Speaks the real SRP + AES-GCM wire format to the
// unmodified src/protocol.js over a fake chrome.runtime port. Dummy PINs and credentials only.
import { webcrypto } from 'node:crypto';
import { performance } from 'node:perf_hooks';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const crypt = await import(new URL('../../src/crypto.js', import.meta.url));
const { sha256, bigIntToBytes, bytesToBigInt, padBytes, utf8ToBytes, mod, powmod, bytesToHex, hexToBytes, randomBytes, concatBytes } = crypt;

const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
const realDateNow = Date.now;

const N = BigInt(
  '0x' +
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF',
);
const NB = 384;
const g = 5n;
const hex = (bytes) => '0x' + bytesToHex(bytes);
const b64json = (o) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64');
const unb64json = (s) => JSON.parse(Buffer.from(s, 'base64').toString('utf8'));

// RFC 5054 server side, independent of the client's SRPSession
class SrpServer {
  constructor(pin, salt) {
    this.pin = pin;
    this.salt = salt;
  }
  async start(username, A) {
    this.username = username;
    this.A = A;
    const x = bytesToBigInt(await sha256(this.salt, await sha256(utf8ToBytes(username + ':' + this.pin))));
    this.v = powmod(g, x, N);
    this.b = bytesToBigInt(randomBytes(32));
    const k = bytesToBigInt(await sha256(bigIntToBytes(N), padBytes(bigIntToBytes(g), NB)));
    this.B = mod(mod(k * this.v, N) + powmod(g, this.b, N), N);
    return this.B;
  }
  async key() {
    const u = bytesToBigInt(await sha256(padBytes(bigIntToBytes(this.A), NB), padBytes(bigIntToBytes(this.B), NB)));
    const S = powmod(mod(this.A * powmod(this.v, u, N), N), this.b, N);
    return bytesToBigInt(await sha256(bigIntToBytes(S)));
  }
  async expectedM(K) {
    const hN = await sha256(bigIntToBytes(N));
    const hg = await sha256(padBytes(bigIntToBytes(g), NB));
    const xored = hN.map((b, i) => b ^ hg[i]);
    return sha256(xored, await sha256(utf8ToBytes(this.username)), this.salt,
      bigIntToBytes(this.A), bigIntToBytes(this.B), padBytes(bigIntToBytes(K), 32));
  }
  async hamk(m, K) {
    return sha256(bigIntToBytes(this.A), m, padBytes(bigIntToBytes(K), 32));
  }
}

function defaultAnswer(cmd, plain) {
  const site = plain.URL || (plain.frameURLs?.[0] ? new URL(plain.frameURLs[0]).hostname : '');
  if (cmd === 4) return { STATUS: 0, Entries: [{ USR: `dummy@${site}`, sites: [site] }] };
  if (cmd === 5) return { STATUS: 0, Entries: [{ USR: plain.USR, PWD: `DUMMY-PASSWORD-${site}`, sites: [site] }] };
  return { STATUS: 3 };
}

export class FakeHelper {
  constructor() {
    this.capabilities = { shouldUseBase64: false, canFillOneTimeCodes: true };
    this.ports = [];
    this.requests = [];
    // hold keys: a command number, or 'm0' / 'm2' for the two handshake steps
    this.hold = new Set();
    this.held = [];
    this.codes = [];
    this.ackSaves = true;
    this.answer = defaultAnswer;
    this.runtime = { lastError: undefined, connectNative: () => this._open() };
    globalThis.chrome = { runtime: this.runtime };
  }

  _open() {
    const port = {
      closed: false,
      messageListeners: [],
      disconnectListeners: [],
      onMessage: { addListener: (fn) => port.messageListeners.push(fn) },
      onDisconnect: { addListener: (fn) => port.disconnectListeners.push(fn) },
      postMessage: (msg) => {
        if (port.closed) throw new Error('Attempting to use a disconnected port object');
        const request = { port, cmd: msg.cmd, msg };
        this.requests.push(request);
        // a request the helper cant read (wrong key, old session) is recorded, not thrown
        request.done = this._handle(port, msg, request).catch((e) => {
          request.error = e;
        });
      },
      disconnect: () => {
        port.closed = true;
      },
    };
    this.ports.push(port);
    return port;
  }

  // replies are asynchronous like Chrome's, and still reach a port whose message was already in flight
  deliver(port, msg) {
    setImmediate(() => port.messageListeners.forEach((fn) => fn(msg)));
  }

  nativeDisconnect(port, message) {
    port.closed = true;
    this.runtime.lastError = message ? { message } : undefined;
    try {
      port.disconnectListeners.forEach((fn) => fn(port));
    } finally {
      this.runtime.lastError = undefined;
    }
  }

  _reply(port, key, msg) {
    if (!msg) return;
    if (this.hold.has(key)) {
      const held = { port, key, msg, release: () => this.deliver(port, msg) };
      this.held.push(held);
      return;
    }
    this.deliver(port, msg);
  }

  async _handle(port, msg, request) {
    if (msg.cmd === 14) return this._reply(port, 14, { cmd: 14, capabilities: this.capabilities });
    if (msg.cmd === 2) {
      const pake = unb64json(msg.msg.PAKE);
      if (msg.msg.QID === 'm0') {
        const pin = String(100000 + this.codes.length * 7919).slice(0, 6);
        this.codes.push(pin);
        const salt = randomBytes(16);
        port.srp = new SrpServer(pin, salt);
        port.username = pake.TID;
        port.key = undefined;
        const B = await port.srp.start(pake.TID, bytesToBigInt(hexToBytes(pake.A)));
        return this._reply(port, 'm0', { cmd: 2, payload: { PAKE: b64json({ TID: pake.TID, MSG: 1, PROTO: 1, B: hex(bigIntToBytes(B)), s: hex(salt) }) } });
      }
      const srp = port.srp;
      port.srp = undefined;
      if (!srp) return this._reply(port, 'm2', { cmd: 2, payload: { PAKE: b64json({ TID: pake.TID, MSG: 3, ErrCode: 1 }) } });
      const K = await srp.key();
      const m = hexToBytes(pake.M);
      if (Buffer.compare(Buffer.from(await srp.expectedM(K)), Buffer.from(m)) !== 0) {
        return this._reply(port, 'm2', { cmd: 2, payload: { PAKE: b64json({ TID: pake.TID, MSG: 3, ErrCode: 1 }) } });
      }
      port.key = await crypto.subtle.importKey('raw', padBytes(bigIntToBytes(K), 32).slice(0, 16), 'AES-GCM', false, ['encrypt', 'decrypt']);
      return this._reply(port, 'm2', { cmd: 2, payload: { PAKE: b64json({ TID: pake.TID, MSG: 3, ErrCode: 0, HAMK: hex(await srp.hamk(m, K)) }) } });
    }
    if (!msg.payload?.SMSG || !port.key) return;
    // client sends ciphertext||iv
    const sealed = hexToBytes(JSON.parse(msg.payload.SMSG).SDATA);
    const plain = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: sealed.slice(-16) }, port.key, sealed.slice(0, -16))));
    request.plain = plain;
    if (msg.cmd === 6) return this.ackSaves ? this._reply(port, 6, { cmd: 6 }) : undefined;
    const answer = this.answer(msg.cmd, plain);
    if (!answer) return;
    // helper replies iv||ciphertext
    const iv = randomBytes(16);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, port.key, utf8ToBytes(JSON.stringify(answer))));
    this._reply(port, msg.cmd, { cmd: msg.cmd, payload: { SMSG: JSON.stringify({ TID: port.username, SDATA: hex(concatBytes(iv, ct)) }) } });
  }

  sent(cmd, port) {
    return this.requests.filter((r) => r.cmd === cmd && (!port || r.port === port));
  }
}

// protocol timeouts and Date.now run on this clock, everything else stays real
export function installClock(t) {
  let now = 1_700_000_000_000;
  const timers = new Map();
  globalThis.setTimeout = (fn, ms = 0) => {
    const id = {};
    timers.set(id, { fn, at: now + ms });
    return id;
  };
  globalThis.clearTimeout = (id) => void timers.delete(id);
  Date.now = () => now;
  t.after(() => {
    globalThis.setTimeout = realSetTimeout;
    globalThis.clearTimeout = realClearTimeout;
    Date.now = realDateNow;
  });
  return {
    advance(ms) {
      now += ms;
      for (const [id, timer] of [...timers].sort((a, b) => a[1].at - b[1].at)) {
        if (timer.at <= now && timers.has(id)) {
          timers.delete(id);
          timer.fn();
        }
      }
    },
  };
}

export const tick = () => new Promise((resolve) => setImmediate(resolve));

export async function until(condition, label = 'condition', ms = 15_000) {
  const end = performance.now() + ms;
  while (!condition()) {
    if (performance.now() > end) throw new Error(`timed out waiting for ${label}`);
    await tick();
  }
}

// a promise that never settles is the bug under test, so fail instead of hanging
export function within(promise, label = 'promise to settle', ms = 15_000) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = realSetTimeout(() => reject(new Error(`timed out waiting for ${label}`)), ms);
    }),
  ]).finally(() => realClearTimeout(timer));
}

// holds calls to one WebCrypto method until opened, to land a reset in the middle of async crypto
export function gateSubtle(t, method) {
  const subtle = globalThis.crypto.subtle;
  const real = subtle[method];
  const own = Object.getOwnPropertyDescriptor(subtle, method);
  let open;
  const gate = new Promise((resolve) => (open = resolve));
  // later calls go straight through, only the ones already started stay held until open()
  const restore = () => {
    if (own) Object.defineProperty(subtle, method, own);
    else delete subtle[method];
  };
  const state = { started: 0, open, restore };
  subtle[method] = function (...args) {
    state.started++;
    return gate.then(() => real.apply(subtle, args));
  };
  t.after(state.restore);
  return state;
}

export async function pair(client, helper) {
  await client.connect();
  await client.requestChallenge();
  await client.verifyPin(helper.codes.at(-1));
}
