// Isolated manual UI preview. No extension APIs, native helper, or vault access.
// Run: node test-harness/security/preview.mjs
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';

const root = new URL('../../', import.meta.url);
const mock = `
const params = new URLSearchParams(location.search);
let state = params.has('pin') ? 'needs_pin' : params.has('nohelper') ? 'no_helper' : params.has('connecting') ? 'disconnected' : 'unlocked';
const target = { tabId: 7, frameId: 0, documentId: 'dummy-doc', url: 'https://example.test/login', origin: 'https://example.test' };
const note = document.createElement('p');
note.style.cssText = 'padding:12px;font:12px system-ui;color:#777';
note.textContent = 'Preview · dummy accounts only';
document.body.append(note);
window.chrome = {
  runtime: {
    onMessage: { addListener() {} },
    sendNativeMessage(host, body, cb) { cb({ error: 'Preview: helper disabled' }); },
    sendMessage(msg, cb) {
      let result = { ok: true };
      if (msg.type === 'getState' || msg.type === 'requestChallenge') result = { ok: true, state, caps: { newPasswordSheet: true } };
      if (msg.type === 'getPageTarget') result.target = target;
      if (msg.type === 'getLogins') result.logins = params.has('empty') ? [] : [{ username: 'personal@example.test' }, { username: 'work@example.test' }];
      if (msg.type === 'getOneTimeCodes') result.rows = params.has('empty') ? [] : [{ id: 'dummy-otp', source: 'totp', username: 'personal@example.test', domain: 'example.test' }];
      if (msg.type === 'verifyPin') { state = 'unlocked'; result.state = state; }
      if (msg.type === 'fillOnPage' || msg.type === 'fillOneTimeCode') {
        note.textContent = 'Dummy action: ' + msg.type + ' ' + (msg.loginName?.username || msg.id);
        result = { ok: false, error: 'Preview: no real fill' };
      }
      queueMicrotask(() => cb(result));
    },
  },
  storage: { local: { get(defaults, cb) { cb(defaults); }, set() {} } },
  tabs: { async sendMessage() { return {}; } },
};
`;
const routes = new Map([
  ['/popup.css', ['src/popup.css', 'text/css']],
  ['/popup.js', ['src/popup.js', 'text/javascript']],
  ['/icons/icon48.png', ['icons/icon48.png', 'image/png']],
  ['/icons/keychain.svg', ['icons/keychain.svg', 'image/svg+xml']],
  ['/icons/keychain-mini.svg', ['icons/keychain-mini.svg', 'image/svg+xml']],
  ['/icons/ui.svg', ['icons/ui.svg', 'image/svg+xml']],
]);
const server = createServer((req, res) => {
  const path = new URL(req.url, 'http://127.0.0.1').pathname;
  res.setHeader('Cache-Control', 'no-store');
  if (path === '/') {
    res.setHeader('Content-Type', 'text/html');
    return res.end(readFileSync(new URL('src/popup.html', root), 'utf8')
      .replace('<script type="module"', '<script src="/mock.js"></script><script type="module"'));
  }
  if (path === '/mock.js') { res.setHeader('Content-Type', 'text/javascript'); return res.end(mock); }
  const route = routes.get(path);
  if (!route) { res.writeHead(404); return res.end(); }
  res.setHeader('Content-Type', route[1]);
  res.end(readFileSync(new URL(route[0], root)));
});
server.listen(8787, '127.0.0.1', () => console.log('Dummy preview: http://127.0.0.1:8787/ (pairing: /?pin)'));
