// alarm keep-alive holds the MV3 worker so the PIN isnt re-prompted every idle-out

import { ApplePasswords, State } from "./protocol.js";

const client = new ApplePasswords();
let secretGeneration = 0;

client.onStateChange((s) => {
  if (s !== State.Unlocked) {
    secretGeneration++;
    pwCacheClear();
    clearEntries(otpByDocument);
  }
  const icon = s === State.Unlocked ? "toolbar" : "toolbar-off";
  chrome.action.setIcon({ path: { 16: `/icons/${icon}16.png`, 32: `/icons/${icon}32.png` } });
  broadcast({ type: "state", state: s });
});

// one attempt per challenge, never a retry loop, a wrong read burns the code. only when the
// user asks for a code (popup, unlock click), never at browser launch
const AUTOPAIR_HOST = "com.openpasswords.autopair";
let autoPairBusy = false;
let autoPairError = null;

function autoPairEnabled() {
  return new Promise((r) => chrome.storage.local.get({ autoPair: false }, (o) => r(!!o.autoPair)));
}

function autoPairMsg(body) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(AUTOPAIR_HOST, body, (r) => {
        const err = chrome.runtime.lastError;
        resolve(err ? { ok: false, error: err.message } : r || { ok: false, error: "no reply" });
      });
    } catch (e) {
      resolve({ ok: false, error: String(e?.message ?? e) });
    }
  });
}

async function tryAutoPair(reason) {
  if (autoPairBusy || client.state !== State.NeedsPin) return false;
  if (!(await autoPairEnabled())) return false;
  autoPairBusy = true;
  try {
    // reuse a code already on screen rather than replacing it under the user
    await withTimeout(client.requestChallenge({ ifNeeded: true }), 8000, "challenge timed out");
    const res = await autoPairMsg({ action: "read", timeoutMs: 6000 });
    if (!res.ok || !res.code) {
      autoPairError = res.error || "no code visible";
      console.debug("[Open Passwords] auto-pair skipped:", autoPairError, reason);
      return false;
    }
    await withTimeout(client.verifyPin(res.code), 8000, "verification timed out");
    autoPairError = null;
    if (client.ready) {
      flushPendingSaves();
    }
    return client.ready;
  } catch (e) {
    autoPairError = String(e?.message ?? e);
    console.debug("[Open Passwords] auto-pair failed:", autoPairError, reason);
    return false;
  } finally {
    autoPairBusy = false;
  }
}

client.onOneTimeCodeAvailable(async () => {
  try {
    const tab = await activeTab();
    if (tab?.id == null) return;
    clearEntries(otpByDocument, (entry) => entry.target.tabId === tab.id);
    chrome.tabs.sendMessage(tab.id, { type: "oneTimeCodeAvailable" }).catch(() => {});
  } catch (_) {}
});

// Code selections belong to a browser document, never just a reusable tab ID.
const otpByDocument = new Map();
const OTP_LIST_TTL_MS = 120_000;

function forgetEntry(map, key) {
  clearTimeout(map.get(key)?.timer);
  map.delete(key);
}
function clearEntries(map, matches = () => true) {
  for (const [key, entry] of map) if (matches(entry)) forgetEntry(map, key);
}
function rememberEntry(map, key, value, ttl) {
  forgetEntry(map, key);
  map.set(key, { ...value, expiresAt: Date.now() + ttl,
    timer: setTimeout(() => forgetEntry(map, key), ttl) });
}
function readEntry(map, key) {
  const entry = map.get(key);
  if (entry && Date.now() >= entry.expiresAt) {
    forgetEntry(map, key);
    return undefined;
  }
  return entry;
}
function documentKey(target) {
  return `${target.tabId}:${target.documentId}`;
}

async function listOneTimeCodes(target) {
  const generation = secretGeneration;
  const { entries, requiresAuth } = await client.getOneTimeCodes(target.tabId, target.frameId, [target.url]);
  await checkTarget(target);
  checkSession(generation);
  const rows = entries.map((e) => ({ ...e, id: crypto.randomUUID() }));
  rememberEntry(otpByDocument, documentKey(target), { target, rows }, OTP_LIST_TTL_MS);
  return { rows: rows.map(({ id, source, username, domain }) => ({ id, source, username, domain })), requiresAuth };
}

async function resolveOneTimeCode(target, id) {
  const cached = readEntry(otpByDocument, documentKey(target));
  if (!cached || !sameTarget(cached.target, target)) throw new Error("Code list expired. Focus the field again.");
  const entry = cached.rows.find((row) => row.id === id);
  if (!entry) throw new Error("Code selection expired. Focus the field again.");
  if (entry.source !== "totp") return entry.code;
  const fresh = await client.readOneTimeCode(target.tabId, target.frameId, [target.url], entry.username);
  const match = fresh.find((e) => e.source === "totp" && e.username === entry.username && e.domain === entry.domain);
  if (!match?.code) throw new Error("No matching verification code returned.");
  return match.code;
}

function broadcast(msg) {
  chrome.runtime.sendMessage(msg).catch(() => {});
}

const mruByHost = new Map();
function recordMru(host, username) {
  if (!host || !username) return;
  const u = username.toLowerCase();
  const arr = (mruByHost.get(host) || []).filter((x) => x !== u);
  arr.unshift(u);
  mruByHost.set(host, arr.slice(0, 10));
}
function orderByMru(host, logins) {
  const order = mruByHost.get(host);
  if (!order || !order.length) return logins;
  const rank = (u) => {
    const i = order.indexOf((u || "").toLowerCase());
    return i === -1 ? Infinity : i;
  };
  return [...logins].sort((a, b) => rank(a.username) - rank(b.username));
}

// "" lets the native sheet ask, null saves nothing
function pickSaveTarget({ host, existing, detected, generated, newPwCtx }) {
  const matched = detected && existing.find((u) => u.toLowerCase() === detected.toLowerCase());
  // update only on a new password, stay quiet on a plain re-login
  if (matched) return generated || newPwCtx ? matched : null;
  if (detected) return detected;
  // attach to the MRU account, apple's sheet lets the user re-pick
  if (newPwCtx && existing.length) {
    return orderByMru(host, existing.map((u) => ({ username: u })))[0].username;
  }
  if (generated) return "";
  return null;
}

// a reset can navigate away, so stash saves that arrived while locked and flush on unlock.
// keyed by host + username, newest wins, an explicit Lock drops them all
const pendingSaves = new Map();
function queuePendingSave(save) {
  rememberEntry(pendingSaves, `${save.host} ${(save.detected || "").toLowerCase()}`, save, PW_CACHE_TTL_MS);
  while (pendingSaves.size > 10) forgetEntry(pendingSaves, pendingSaves.keys().next().value);
}
async function flushPendingSaves() {
  if (!client.ready || !pendingSaves.size) return;
  const generation = secretGeneration;
  for (const key of [...pendingSaves.keys()]) {
    const queued = readEntry(pendingSaves, key);
    if (!queued) continue;
    // the same entry must still be queued, unexpired, and in this unlock, after every wait
    const live = () => generation === secretGeneration && client.ready && readEntry(pendingSaves, key) === queued;
    if (!live()) return;
    try {
      let existing = [];
      try {
        existing = (await client.getLoginNamesForURL(queued.tabId, queued.frameUrl))
          .map((l) => l.username)
          .filter(Boolean);
      } catch {}
      if (!live()) continue;
      const target = pickSaveTarget({ ...queued, existing });
      if (target === null) {
        forgetEntry(pendingSaves, key);
        continue;
      }
      // checked again inside the native queue, a Lock or expiry while waiting there drops it
      await client.saveLogin(queued.tabId, queued.frameUrl, target, queued.password, {
        shouldSend: () => {
          if (!live()) return false;
          forgetEntry(pendingSaves, key);
          return true;
        },
      });
    } catch {}
  }
}
function dropPendingSaves() {
  clearEntries(pendingSaves);
}

// keeps internal spaces so distinct usernames arent merged
function normUsername(u) {
  return (u || "")
    .normalize("NFC")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .trim()
    .toLowerCase();
}

// helper returns the same username for www + apex entries, fills look up by username so dupes are useless
function uniqueByUsername(logins) {
  const seen = new Set();
  return logins.filter((l) => {
    const k = normUsername(l.username);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

// Short repeat fills reuse a credential only within the same document and origin.
const PW_CACHE_TTL_MS = 120_000;
const pwCache = new Map();
function pwCacheKey(target, username) {
  return JSON.stringify([target.tabId, target.documentId, target.origin, username || ""]);
}
function pwCacheGet(target, username) {
  return readEntry(pwCache, pwCacheKey(target, username))?.cred;
}
function pwCacheSet(target, cred) {
  rememberEntry(pwCache, pwCacheKey(target, cred.username), { target, cred }, PW_CACHE_TTL_MS);
}
function pwCacheClear() {
  clearEntries(pwCache);
}

async function withTimeout(promise, ms, label) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label || "timed out")), ms);
    })]);
  } finally {
    clearTimeout(timer);
  }
}

// defeat the MV3 ~30s idle shutdown that kills the session
const KEEPALIVE_ALARM = "open-passwords-keepalive";
chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 0.4 });
chrome.alarms.onAlarm.addListener((a) => {
  if (a.name !== KEEPALIVE_ALARM) return;
  // touching an extension API resets the idle timer
  chrome.runtime.getPlatformInfo(() => void chrome.runtime.lastError);
});

async function ensureConnected() {
  if (client.state === State.Disconnected) {
    try {
      await client.connect();
    } catch (e) {
      // surfaced via state change (NoHelper / Disconnected)
    }
  }
}

chrome.runtime.onStartup.addListener(ensureConnected);
chrome.runtime.onInstalled.addListener(ensureConnected);
ensureConnected();

function suppressChromeAutofill() {
  const svc = chrome.privacy?.services;
  if (!svc?.passwordSavingEnabled) return;
  // credit-card autofill is never touched, google pay keeps working
  chrome.storage?.local?.get({ suppressSaveBubble: true, suppressAddressAutofill: false }, (o) => {
    if (chrome.runtime.lastError) return;
    try {
      if (o.suppressSaveBubble) {
        svc.passwordSavingEnabled.set({ value: false }, () => void chrome.runtime.lastError);
      }
      if (o.suppressAddressAutofill && svc.autofillAddressEnabled) {
        svc.autofillAddressEnabled.set({ value: false }, () => void chrome.runtime.lastError);
      }
    } catch (_) {}
  });
}
chrome.runtime.onInstalled.addListener(suppressChromeAutofill);
chrome.runtime.onStartup.addListener(suppressChromeAutofill);
suppressChromeAutofill();

// content messages carry sender.tab, the popup never does
function isFromOwnUi(sender) {
  return sender.id === chrome.runtime.id && sender.tab === undefined &&
    sender.url === chrome.runtime.getURL("src/popup.html");
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function registrableHost(u) {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// loopback and RFC 6761 reserved TLDs are the only non-HTTPS origins treated as fillable
function isLocalDevHost(host) {
  return (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "[::1]" ||
    host?.endsWith(".localhost") ||
    host?.endsWith(".test")
  );
}

function secureOrigin(url) {
  const u = new URL(url);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && isLocalDevHost(u.hostname))) {
    throw new Error("Open Passwords only fills secure HTTPS pages.");
  }
  return u.origin;
}

function targetFromSender(sender) {
  const origin = secureOrigin(sender.url);
  if (sender.tab?.id == null || sender.frameId == null || !sender.documentId ||
      sender.origin !== origin || (sender.documentLifecycle && sender.documentLifecycle !== "active")) {
    throw new Error("This page cannot receive credentials.");
  }
  return { tabId: sender.tab.id, frameId: sender.frameId, documentId: sender.documentId, url: sender.url, origin };
}

function sameTarget(a, b) {
  return a && b && a.tabId === b.tabId && a.frameId === b.frameId &&
    a.documentId === b.documentId && a.origin === b.origin && a.url === b.url;
}

// Obtain documentId from Chrome's MessageSender via the isolated content script.
// This avoids an extra webNavigation permission or a page-controlled document ID.
async function pageTarget() {
  const tab = await activeTab();
  secureOrigin(tab?.url);
  const reply = await chrome.tabs.sendMessage(tab.id, { type: "getFrameContext" }, { frameId: 0 });
  const target = reply?.target;
  if (!reply?.ok || target?.tabId !== tab.id || target.frameId !== 0 || target.url !== tab.url) {
    throw new Error("Page changed. Reopen Open Passwords.");
  }
  return target;
}
async function checkTarget(target) {
  if (!target?.documentId || secureOrigin(target.url) !== target.origin) throw new Error("Invalid fill target.");
  const reply = await chrome.tabs.sendMessage(target.tabId, { type: "getFrameContext" }, { documentId: target.documentId });
  if (!reply?.ok || !sameTarget(reply.target, target)) throw new Error("Page changed. Reopen Open Passwords.");
}
async function popupTarget(target) {
  const tab = await activeTab();
  if (tab?.id !== target?.tabId) throw new Error("Tab changed. Reopen Open Passwords.");
  await checkTarget(target);
  return target;
}
function checkSession(generation) {
  if (!client.ready || generation !== secretGeneration) throw new Error("Passwords locked. Unlock and try again.");
}
async function deliver(target, message, generation) {
  await checkTarget(target);
  checkSession(generation);
  return chrome.tabs.sendMessage(target.tabId, { ...message, expectedOrigin: target.origin, expectedUrl: target.url },
    { documentId: target.documentId });
}
async function fillPassword(target, login) {
  await checkTarget(target);
  const generation = secretGeneration;
  checkSession(generation);
  let cred = pwCacheGet(target, login?.username);
  if (!cred) {
    cred = await client.getPasswordForLoginName(target.tabId, target.url, { username: login?.username });
  }
  if (!cred) return false;
  const result = await deliver(target, { type: "fill", username: cred.username, password: cred.password }, generation);
  checkSession(generation);
  if (result?.filled) {
    pwCacheSet(target, cred);
    recordMru(registrableHost(target.url), cred.username);
  }
  return !!result?.filled;
}
async function fillOneTimeCode(target, id) {
  await checkTarget(target);
  const generation = secretGeneration;
  checkSession(generation);
  const code = await resolveOneTimeCode(target, id);
  const result = await deliver(target, { type: "fillOtp", code }, generation);
  checkSession(generation);
  forgetEntry(otpByDocument, documentKey(target));
  // the code only goes back to the popup to show when the page had nowhere to put it
  return result?.filled ? { filled: true } : { filled: false, code };
}

chrome.tabs.onRemoved.addListener((tabId) => {
  clearEntries(pwCache, (e) => e.target.tabId === tabId);
  clearEntries(otpByDocument, (e) => e.target.tabId === tabId);
});

// only these from a content script, none returns a password to the page
const CONTENT_ALLOWED = new Set([
  "inlineLogins",
  "inlineFill",
  "inlineOneTimeCodes",
  "inlineFillOneTimeCode",
  "getFrameContext",
  "openPopup",
  "resolveSave",
]);

chrome.commands?.onCommand.addListener(async (command) => {
  if (command !== "fill-login") return;
  const tab = await activeTab();
  if (tab?.id == null) return;
  chrome.tabs.sendMessage(tab.id, { type: "shortcut" }).catch(() => {});
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      const fromUi = isFromOwnUi(sender);
      const fromContent = sender.id === chrome.runtime.id && sender.tab !== undefined;
      if (!fromUi && !(fromContent && CONTENT_ALLOWED.has(msg?.type))) {
        sendResponse({ ok: false, error: "forbidden" });
        return;
      }

      switch (msg?.type) {
        case "getFrameContext":
          return sendResponse({ ok: true, target: targetFromSender(sender) });

        case "getPageTarget":
          return sendResponse({ ok: true, target: await pageTarget() });

        case "openPopup": {
          const target = targetFromSender(sender);
          const tab = await activeTab();
          if (tab?.id !== target.tabId) throw new Error("Select this tab first.");
          await checkTarget(target);
          await chrome.action.openPopup();
          return sendResponse({ ok: true });
        }

        case "inlineLogins": {
          const target = targetFromSender(sender);
          await ensureConnected();
          if (!client.ready) return sendResponse({ ok: true, locked: true, logins: [] });
          const generation = secretGeneration;
          const logins = await client.getLoginNamesForURL(target.tabId, target.url);
          await checkTarget(target);
          checkSession(generation);
          return sendResponse({ ok: true, locked: false,
            logins: uniqueByUsername(orderByMru(registrableHost(target.url), logins)) });
        }

        case "inlineOneTimeCodes": {
          const target = targetFromSender(sender);
          await ensureConnected();
          if (!client.ready) return sendResponse({ ok: true, locked: true, supported: client.canFillOneTimeCodes, rows: [] });
          if (!client.canFillOneTimeCodes) return sendResponse({ ok: true, locked: false, supported: false, rows: [] });
          return sendResponse({ ok: true, locked: false, supported: true, ...await listOneTimeCodes(target) });
        }

        case "inlineFillOneTimeCode": {
          const result = await fillOneTimeCode(targetFromSender(sender), msg.id);
          return sendResponse({ ok: true, filled: result.filled });
        }

        case "inlineFill":
          return sendResponse({ ok: true, filled: await fillPassword(targetFromSender(sender), msg.loginName) });

        case "resolveSave": {
          // saving here so a submit that navigates cant kill it
          const frameUrl = targetFromSender(sender).url;
          const host = registrableHost(frameUrl);
          if (!msg.password) return sendResponse({ ok: false, error: "no password" });
          const detected = (msg.username || "").trim();
          const generated = !!msg.generated;
          const newPwCtx = !!msg.newPwCtx;
          await ensureConnected();

          // locked: stash a new-password save for unlock, a plain re-login isnt worth deferring
          if (!client.ready) {
            if (generated || newPwCtx) {
              queuePendingSave({
                host,
                frameUrl,
                tabId: sender.tab.id,
                detected,
                password: msg.password,
                generated,
                newPwCtx,
              });
            }
            return sendResponse({ ok: true, saved: false, locked: true });
          }

          let existing = [];
          try {
            existing = (await client.getLoginNamesForURL(sender.tab.id, frameUrl))
              .map((l) => l.username)
              .filter(Boolean);
          } catch {}
          const target = pickSaveTarget({ host, existing, detected, generated, newPwCtx });
          if (target === null) return sendResponse({ ok: true, saved: false, skipped: true });
          await client.saveLogin(sender.tab.id, frameUrl, target, msg.password);
          sendResponse({ ok: true, saved: true });
          break;
        }

        case "getState":
          await ensureConnected();
          sendResponse({
            ok: true,
            state: client.state,
            hasChallenge: client.hasChallenge,
            caps: {
              oneTimeCodes: client.canFillOneTimeCodes,
              newPasswordSheet: client.canOpenPasswordsAppToNewPasswordSheet,
              setUpTotp: client.canSetUpTotp,
            },
            autoPairError,
          });
          break;

        case "autoPairCheck": {
          const r = await autoPairMsg({ action: "check" });
          sendResponse(r);
          break;
        }

        case "getOneTimeCodes": {
          const target = await popupTarget(msg.target);
          if (!client.ready) return sendResponse({ ok: true, rows: [] });
          if (!client.canFillOneTimeCodes) return sendResponse({ ok: true, supported: false, rows: [] });
          return sendResponse({ ok: true, supported: true, ...await listOneTimeCodes(target) });
        }

        case "fillOneTimeCode": {
          const target = await popupTarget(msg.target);
          return sendResponse({ ok: true, ...await fillOneTimeCode(target, msg.id) });
        }

        case "openPasswordsApp": {
          const target = await popupTarget(msg.target);
          const url = target.url;
          await ensureConnected();
          if (msg.mode === "totp") {
            if (!msg.uri || !/^(apple-)?otpauth:\/\//i.test(msg.uri)) return sendResponse({ ok: false, error: "no otpauth URI" });
            client.launchPasswordsApp({ totpUri: msg.uri, totpPageUrl: url });
          } else if (msg.mode === "new") {
            client.launchPasswordsApp({ newPasswordUrl: url });
          } else {
            client.launchPasswordsApp({ searchUrl: url });
          }
          sendResponse({ ok: true });
          break;
        }

        case "connect":
          await ensureConnected();
          sendResponse({ ok: true, state: client.state });
          break;

        case "requestChallenge":
          // Pairing is only available in the extension popup.
          await ensureConnected();
          await withTimeout(client.requestChallenge({ ifNeeded: !!msg.ifNeeded }), 8000, "challenge timed out");
          // not awaited, the UI shows its PIN box while auto-pair reads the code
          tryAutoPair("request");
          sendResponse({ ok: true, state: client.state, hasChallenge: client.hasChallenge });
          break;

        case "verifyPin": {
          await ensureConnected();
          try {
            await withTimeout(client.verifyPin(msg.pin), 8000, "verification timed out");
          } catch (e) {
            // a spent challenge cant be retried, put a fresh code up or the user retypes a dead code forever
            let newCode = e?.code === "challenge_reissued";
            if (!newCode && !client.hasChallenge && client.state === State.NeedsPin) {
              try {
                await withTimeout(client.requestChallenge(), 8000, "challenge timed out");
                newCode = true;
              } catch (_) {}
            }
            return sendResponse({
              ok: false,
              error: String(e?.message ?? e),
              newCode,
              state: client.state,
            });
          }
          sendResponse({ ok: true, state: client.state });
          if (client.ready) flushPendingSaves();
          break;
        }

        case "getLogins": {
          const target = await popupTarget(msg.target);
          const generation = secretGeneration;
          const logins = await client.getLoginNamesForURL(target.tabId, target.url);
          await checkTarget(target);
          checkSession(generation);
          return sendResponse({ ok: true, logins: uniqueByUsername(orderByMru(registrableHost(target.url), logins)) });
        }

        case "fillOnPage":
          return sendResponse({ ok: true, filled: await fillPassword(await popupTarget(msg.target), msg.loginName) });

        case "clearCache":
          pwCacheClear();
          clearEntries(otpByDocument);
          sendResponse({ ok: true });
          break;

        case "disconnect":
          // an explicit Lock means nothing typed earlier should reach the vault later
          dropPendingSaves();
          client.disconnect();
          sendResponse({ ok: true, state: client.state });
          break;

        default:
          sendResponse({ ok: false, error: "unknown message" });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message ?? e), state: client.state });
    }
  })();
  return true;
});
