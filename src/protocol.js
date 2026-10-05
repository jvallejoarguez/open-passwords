// ported from au2001/icloud-passwords-firefox (Apache-2.0), see NOTICE

import { SRPSession, SecretSessionVersion, MSGType } from "./srp.js";
import {
  bytesToBase64,
  base64ToBytes,
  bytesToUtf8,
  bigIntToBytes,
  bytesToBigInt,
  constantTimeEqual,
  QueryStatus,
  queryStatusError,
} from "./crypto.js";

const NATIVE_HOST = "com.apple.passwordmanager";
const BROWSER_NAME = "Chrome";
const VERSION = "1.0";
// past this we re-prompt instead of verifying against a code the user lost track of
const CHALLENGE_TTL_MS = 3 * 60_000;
// a timed-out reply that never arrives would block its command forever, so past this we re-pair instead of reusing it
const STALE_REPLY_RESET_MS = 30_000;

// callers show "new code" wording for this, retyping the old code can never work
function challengeError(message) {
  const e = new Error(message);
  e.code = "challenge_reissued";
  return e;
}

// numbering matches the helper's own ExtensionCommand enum (and apple's extension)
export const Command = {
  END: 0,
  HANDSHAKE: 2,
  SET_ICON_AND_TITLE: 3,
  GET_LOGIN_NAMES_FOR_URL: 4,
  GET_PASSWORD_FOR_LOGIN_NAME: 5,
  SET_PASSWORD_FOR_LOGIN_NAME_URL: 6,
  NEW_ACCOUNT_FOR_URL: 7,
  TAB_EVENT: 8,
  PASSWORDS_DISABLED: 9,
  RELOGIN_NEEDED: 10,
  LAUNCH_PASSWORDS_APP: 13, // also carries "new password sheet" and "set up TOTP" variants
  GET_CAPABILITIES: 14,
  ONE_TIME_CODE_AVAILABLE: 15, // helper -> us, unsolicited: a code just arrived (Messages)
  GET_ONE_TIME_CODES: 16,
  DID_FILL_ONE_TIME_CODE: 17, // read the current TOTP value right before filling it
  SET_UP_TOTP_GENERATOR: 18, // status reply to the set-up-TOTP variant of cmd 13
  OPEN_URL_IN_SAFARI: 1984,
};

const QueryId = {
  [4]: "CmdGetLoginNames4URL",
  [5]: "CmdGetPassword4LoginName",
  [16]: "CmdGetOneTimeCodes",
  [17]: "CmdDidFillOneTimeCode",
};

const Action = { UPDATE: 1, SEARCH: 2, ADD_NEW: 3, MAYBE_ADD: 4, GHOST_SEARCH: 5 };

export const State = {
  Disconnected: "disconnected",
  NeedsPin: "needs_pin",
  Unlocked: "unlocked",
  NoHelper: "no_helper",
};

function jsonToBase64(obj) {
  return bytesToBase64(new TextEncoder().encode(JSON.stringify(obj)));
}

// totp entries can arrive without a code, the value is read at fill time
function normalizeOtpEntries(entries) {
  return (Array.isArray(entries) ? entries : [])
    .map((e) => ({
      source: String(e.source || ""),
      username: e.username || "",
      domain: e.domain || "",
      code: e.code != null ? String(e.code) : "",
    }))
    .filter((e) => e.code || e.source === "totp");
}

export class ApplePasswords {
  constructor() {
    this.port = undefined;
    this.session = undefined;
    this.capabilities = undefined;
    this.state = State.Disconnected;
    this._waiters = new Map();
    this._onState = () => {};
    this._onOneTimeCode = () => {};
    this._challengeAt = 0;
    this._challengeGen = 0;
    this._challengePending = undefined;
    // bumped for every new port and every reset, work from an older connection never touches a newer one
    this._epoch = 0;
    this._connecting = undefined;
    // replies carry no correlation id, so same-cmd requests collide. serialize everything
    this._lock = Promise.resolve();
  }

  _withLock(fn) {
    const run = this._lock.then(fn, fn);
    this._lock = run.then(
      () => {},
      () => {},
    );
    return run;
  }

  // queued work is bound to the connection, session and challenge it was queued under
  _withSession(fn) {
    const ctx = { epoch: this._epoch, session: this.session, challengeGen: this._challengeGen, unlocked: this.ready };
    return this._withLock(() => fn(ctx));
  }

  _live(ctx) {
    return (
      ctx.epoch === this._epoch &&
      ctx.session !== undefined &&
      ctx.session === this.session &&
      ctx.challengeGen === this._challengeGen &&
      (!ctx.unlocked || this.ready)
    );
  }

  // called after every await, so a reset or re-pair in between can never be acted on by older work
  _check(ctx) {
    if (!this._live(ctx)) throw new Error("Apple Passwords session changed. Try again.");
  }

  // the one invalidation path: lock, native disconnect, re-login and ambiguous timeouts all land here
  _reset(error, state = State.Disconnected) {
    this._epoch++;
    const port = this.port;
    this.port = undefined;
    this.session = undefined;
    this._connecting = undefined;
    this._challengeGen++;
    this._challengeAt = 0;
    this._challengePending = undefined;
    // old queued work fails its own checks, new work must not wait behind a reply that will never come
    this._lock = Promise.resolve();
    const waiters = [...this._waiters.values()];
    this._waiters.clear();
    for (const w of waiters) {
      clearTimeout(w.timer);
      w.reject(error);
    }
    if (port) {
      try {
        port.disconnect();
      } catch (_) {}
    }
    this._setState(state);
  }

  onStateChange(fn) {
    this._onState = fn;
  }

  onOneTimeCodeAvailable(fn) {
    this._onOneTimeCode = fn;
  }

  // default false so an older helper hides the feature instead of getting a command it cant handle
  get canFillOneTimeCodes() {
    return this.capabilities?.canFillOneTimeCodes === true;
  }
  get canOpenPasswordsAppToNewPasswordSheet() {
    return this.capabilities?.canOpenPasswordsAppToNewPasswordSheet === true;
  }
  get canSetUpTotp() {
    return this.capabilities?.scanForOTPURI === true;
  }
  get canSaveAccountWithEmptyUserName() {
    return this.capabilities?.canSaveAccountWithEmptyUserName === true;
  }

  _setState(s) {
    if (this.state === s) return;
    this.state = s;
    try {
      this._onState(s);
    } catch (_) {}
  }

  get ready() {
    return (
      this.port !== undefined &&
      this.session !== undefined &&
      this.session.sharedKey !== undefined &&
      this.state === State.Unlocked
    );
  }

  // onTimeout: "stale" keeps a marker that swallows the late reply instead of handing it to the next request,
  // "reset" drops the connection, "ack" treats a missing content-free acknowledgement as success
  _send(cmd, body = {}, timeoutMs = 5000, onTimeout = "stale") {
    if (!this.port) return Promise.reject(new Error("connection closed"));
    // a second request on the same cmd would steal the first one's reply
    const prior = this._waiters.get(cmd);
    if (prior) {
      if (prior.stale && Date.now() - prior.staleAt >= STALE_REPLY_RESET_MS) {
        const e = new Error("Apple Passwords stopped responding. Unlock again.");
        this._reset(e);
        return Promise.reject(e);
      }
      return Promise.reject(
        new Error(prior.stale ? "Apple Passwords is still answering an earlier request. Try again shortly." : "another request is already in flight"),
      );
    }
    return new Promise((resolve, reject) => {
      const entry = { resolve, reject, timer: null, stale: false, staleAt: 0 };
      if (timeoutMs != null) {
        entry.timer = setTimeout(() => {
          if (this._waiters.get(cmd) !== entry) return;
          entry.timer = null;
          if (onTimeout === "ack") {
            this._waiters.delete(cmd);
            return resolve(undefined);
          }
          const e = new Error("timeout waiting for response");
          reject(e);
          if (onTimeout === "reset") return this._reset(e);
          entry.stale = true;
          entry.staleAt = Date.now();
        }, timeoutMs);
      }
      this._waiters.set(cmd, entry);
      try {
        this.port.postMessage({ cmd, ...body });
      } catch (e) {
        clearTimeout(entry.timer);
        if (this._waiters.get(cmd) === entry) this._waiters.delete(cmd);
        reject(e);
      }
    });
  }

  _dispatch(message) {
    const w = this._waiters.get(message.cmd);
    if (w) {
      this._waiters.delete(message.cmd);
      clearTimeout(w.timer);
      // a stale entry only exists to swallow this late reply, nobody is waiting on it anymore
      if (!w.stale) w.resolve(message);
    }
    if (message.cmd === Command.PASSWORDS_DISABLED || message.cmd === Command.RELOGIN_NEEDED) {
      // the helper dropped our session, a fresh connection is the only way pairing works again
      this._reset(new Error("Apple Passwords needs to be unlocked again."));
      return;
    }
    if (message.cmd === Command.ONE_TIME_CODE_AVAILABLE && !w) {
      try {
        this._onOneTimeCode();
      } catch (_) {}
    }
  }

  // never resets an unlocked session, apple's extension re-pairs on every connect
  connect() {
    if (this._connecting) return this._connecting;
    if (this.port) return Promise.resolve();
    let port;
    try {
      port = chrome.runtime.connectNative(NATIVE_HOST);
    } catch (e) {
      this._setState(State.NoHelper);
      return Promise.reject(e);
    }
    const epoch = ++this._epoch;
    this.port = port;

    // a replaced port's late messages or disconnect must never reach the current connection
    port.onMessage.addListener((msg) => {
      if (this.port === port) this._dispatch(msg);
    });
    port.onDisconnect.addListener(() => {
      if (this.port !== port) return;
      const err = chrome.runtime.lastError?.message;
      const state = err && /not found|forbidden|host/i.test(err) ? State.NoHelper : State.Disconnected;
      this._reset(new Error("Apple Passwords disconnected."), state);
    });

    const p = this._send(Command.GET_CAPABILITIES, {}, 5000, "reset").then((reply) => {
      if (epoch !== this._epoch) throw new Error("connection closed");
      const capabilities = reply.capabilities ?? {};
      // helper negotiates the version per handshake via PROTO, so only reject an explicit non-RFC demand
      if (
        capabilities.secretSessionVersion !== undefined &&
        capabilities.secretSessionVersion !== SecretSessionVersion.SRPWithRFCVerification
      ) {
        const e = new Error("unsupported capabilities (expected SRP RFC verification)");
        this._reset(e);
        throw e;
      }
      this.capabilities = capabilities;
      this.session = new SRPSession(capabilities.shouldUseBase64);
      this._setState(State.NeedsPin);
    });
    this._connecting = p;
    const done = () => {
      if (this._connecting === p) this._connecting = undefined;
    };
    p.then(done, done);
    return p;
  }

  // the code on the Mac only belongs to the newest challenge
  get hasChallenge() {
    return (
      this.state === State.NeedsPin &&
      this.session !== undefined &&
      this.session.serverPublicKey !== undefined &&
      this.session.salt !== undefined &&
      Date.now() - this._challengeAt < CHALLENGE_TTL_MS
    );
  }

  // ifNeeded keeps a live prompt, a second code on screen invalidates the one the user is reading
  requestChallenge({ ifNeeded = false } = {}) {
    if (!this.session) return Promise.reject(new Error("not connected"));
    if (ifNeeded && (this.hasChallenge || this.state === State.Unlocked)) return Promise.resolve(false);
    // two prompts would race and only the last code works
    if (this._challengePending) return this._challengePending;
    const p = this._withSession((ctx) => this._issueChallenge(ctx));
    this._challengePending = p;
    const clear = () => {
      if (this._challengePending === p) this._challengePending = undefined;
    };
    p.then(clear, clear);
    return p;
  }

  async _issueChallenge(ctx) {
    this._check(ctx);
    const { session } = ctx;
    session.serverPublicKey = undefined;
    session.salt = undefined;
    session.sharedKey = undefined;
    // this challenge owns the new generation, anything queued for the old keys is now stale
    ctx.challengeGen = ++this._challengeGen;
    ctx.unlocked = false;
    this._setState(State.NeedsPin);

    // a lost hello leaves no safe way to match a late one, start over on a fresh connection
    const reply = await this._send(
      Command.HANDSHAKE,
      {
        msg: {
          QID: "m0",
          PAKE: jsonToBase64({
            TID: session.username,
            MSG: MSGType.ClientKeyExchange,
            A: session.serialize(session.clientPublicKeyBytes),
            VER: VERSION,
            PROTO: [SecretSessionVersion.SRPWithRFCVerification],
          }),
          HSTBRSR: BROWSER_NAME,
        },
      },
      5000,
      "reset",
    );
    this._check(ctx);

    const pake = JSON.parse(bytesToUtf8(base64ToBytes(reply.payload.PAKE)));
    if (pake.TID !== session.username) throw new Error("challenge for another session");
    if (pake.ErrCode !== undefined) throw new Error(`server hello error ${pake.ErrCode}`);
    if (pake.MSG.toString() !== MSGType.ServerKeyExchange.toString()) throw new Error("unexpected server message");
    if (pake.PROTO !== SecretSessionVersion.SRPWithRFCVerification) throw new Error("unsupported protocol");

    const B = bytesToBigInt(session.deserialize(pake.B));
    const s = session.deserialize(pake.s);
    session.setServerPublicKey(B, s);
    this._challengeAt = Date.now();
    this._setState(State.NeedsPin);
    return true;
  }

  // a PIN only matches the challenge it was shown for, so re-issue and ask for the new code
  async verifyPin(pin) {
    if (!this.session) throw new Error("not connected");
    if (!this.hasChallenge) {
      await this.requestChallenge();
      throw challengeError("Enter the new code your Mac is showing now");
    }
    const gen = this._challengeGen;
    return this._withSession(async (ctx) => {
      // re-issued while queued, typed code is for the old prompt
      if (gen !== this._challengeGen) throw challengeError("Enter the new code your Mac is showing now");
      this._check(ctx);
      const { session } = ctx;
      try {
        await session.setSharedKey(pin);
        this._check(ctx);
        const m = await session.computeM();
        this._check(ctx);

        const reply = await this._send(
          Command.HANDSHAKE,
          {
            msg: {
              QID: "m2",
              PAKE: jsonToBase64({
                TID: session.username,
                MSG: MSGType.ClientVerification,
                M: session.serialize(m, false),
              }),
            },
          },
          5000,
          "reset",
        );
        this._check(ctx);

        const pake = JSON.parse(bytesToUtf8(base64ToBytes(reply.payload.PAKE)));
        if (pake.TID !== session.username) throw new Error("verification for another session");
        if (pake.MSG.toString() !== MSGType.ServerVerification.toString()) throw new Error("unexpected server message");
        if (pake.ErrCode === 1) throw new Error("Incorrect code");
        if (pake.ErrCode !== 0 && pake.ErrCode !== undefined) throw new Error(`verification error ${pake.ErrCode}`);

        const hamk = await session.computeHMAC(m);
        if (!constantTimeEqual(session.deserialize(pake.HAMK), hamk)) throw new Error("server HAMK mismatch");

        // only the connection and challenge this code was typed for can be unlocked by it
        this._check(ctx);
        this._setState(State.Unlocked);
      } catch (e) {
        // helper burns the challenge on a failed verify. only this attempt's session is touched, never a newer one
        session.sharedKey = undefined;
        session.serverPublicKey = undefined;
        session.salt = undefined;
        if (this._live(ctx)) this._challengeAt = 0;
        throw e;
      }
    });
  }

  async _encryptedQuery(ctx, cmd, tabId, hostname, payloadBody, timeoutMs, frameId = 0) {
    this._check(ctx);
    const { session } = ctx;
    const sdata = session.serialize(await session.encrypt(payloadBody));
    const body = {
      tabId,
      frameId,
      payload: { QID: QueryId[cmd], SMSG: JSON.stringify({ TID: session.username, SDATA: sdata }) },
    };
    // one-time-code queries carry their URLs inside the encrypted body
    if (hostname != null) body.url = hostname;
    this._check(ctx);
    const reply = await this._send(cmd, body, timeoutMs);
    this._check(ctx);

    let smsg = reply.payload.SMSG;
    if (typeof smsg === "string") smsg = JSON.parse(smsg);
    if (smsg.TID !== session.username) throw new Error("response for another session");
    const data = await session.decrypt(session.deserialize(smsg.SDATA));
    this._check(ctx);
    return JSON.parse(bytesToUtf8(data));
  }

  async getLoginNamesForURL(tabId, url) {
    if (!this.ready) throw new Error("not unlocked");
    const { hostname } = new URL(url);
    return this._withSession(async (ctx) => {
      const res = await this._encryptedQuery(
        ctx,
        Command.GET_LOGIN_NAMES_FOR_URL,
        tabId,
        hostname,
        { ACT: Action.GHOST_SEARCH, URL: hostname },
        5000,
      );
      if (res.STATUS === QueryStatus.Success)
        return (res.Entries ?? []).map((e) => ({ username: e.USR, sites: e.sites }));
      if (res.STATUS === QueryStatus.NoResults) return [];
      throw queryStatusError(res.STATUS);
    });
  }

  async getPasswordForLoginName(tabId, url, loginName) {
    if (!this.ready) throw new Error("not unlocked");
    const { hostname } = new URL(url);
    return this._withSession(async (ctx) => {
      const res = await this._encryptedQuery(
        ctx,
        Command.GET_PASSWORD_FOR_LOGIN_NAME,
        tabId,
        // query by frame hostname, never loginName.sites which a page could point at another origin
        hostname,
        { ACT: Action.SEARCH, URL: hostname, USR: loginName.username },
        null, // no timeout, helper may require Touch ID here
      );
      if (res.STATUS === QueryStatus.Success) {
        const e = (res.Entries ?? [])[0];
        if (!e) return undefined;
        // reply is USR/PWD/customTitle/highLevelDomain/sites, no note or OTP seed
        return { username: e.USR, password: e.PWD, sites: e.sites };
      }
      if (res.STATUS === QueryStatus.NoResults) return undefined;
      throw queryStatusError(res.STATUS);
    });
  }

  // ACT maybeAdd lets the helper decide add-vs-update and drive the native save prompt.
  // shouldSend is asked right before posting, after any queueing, and false skips the save
  async saveLogin(tabId, url, username, password, { shouldSend } = {}) {
    if (!this.ready) throw new Error("not unlocked");
    if (!password) throw new Error("no password to save");
    const { hostname } = new URL(url);
    return this._withSession(async (ctx) => {
      this._check(ctx);
      const { session } = ctx;
      const sdata = session.serialize(
        await session.encrypt({
          ACT: Action.MAYBE_ADD,
          URL: "",
          USR: "",
          PWD: "",
          NURL: hostname,
          NUSR: username ?? "",
          NPWD: password,
        }),
      );
      const body = {
        tabId,
        frameId: 0,
        payload: {
          QID: "CmdNewAccount4URL",
          SMSG: JSON.stringify({ TID: session.username, SDATA: sdata }),
        },
      };
      this._check(ctx);
      if (shouldSend && !shouldSend()) return false;
      // ack is empty and confirmation happens in the native prompt, so a slow ack is not an error.
      // nothing is read from it, so a late ack landing on a later save cant leak anything
      await this._send(Command.SET_PASSWORD_FOR_LOGIN_NAME_URL, body, 3000, "ack");
      return true;
    });
  }

  async getOneTimeCodes(tabId, frameId, frameUrls, username) {
    if (!this.ready) throw new Error("not unlocked");
    if (!this.canFillOneTimeCodes) return { entries: [], requiresAuth: false };
    const body = { ACT: Action.GHOST_SEARCH, TYPE: "oneTimeCodes", frameURLs: frameUrls };
    if (username) body.username = username;
    return this._withSession(async (ctx) => {
      const res = await this._encryptedQuery(ctx, Command.GET_ONE_TIME_CODES, tabId, null, body, 8000, frameId);
      const requiresAuth = !!res.RequiresUserAuthenticationToFill;
      if (res.STATUS === QueryStatus.Success) return { entries: normalizeOtpEntries(res.Entries), requiresAuth };
      if (res.STATUS === QueryStatus.NoResults) return { entries: [], requiresAuth };
      throw queryStatusError(res.STATUS);
    });
  }

  // read at pick time so a code listed earlier isnt filled after it rotated. no timeout, may need Touch ID
  async readOneTimeCode(tabId, frameId, frameUrls, username) {
    if (!this.ready) throw new Error("not unlocked");
    const body = { ACT: Action.SEARCH, TYPE: "oneTimeCodes", frameURLs: frameUrls };
    if (username) body.username = username;
    return this._withSession(async (ctx) => {
      const res = await this._encryptedQuery(ctx, Command.DID_FILL_ONE_TIME_CODE, tabId, null, body, null, frameId);
      if (res.STATUS === QueryStatus.Success) return normalizeOtpEntries(res.Entries);
      if (res.STATUS === QueryStatus.NoResults) return [];
      throw queryStatusError(res.STATUS);
    });
  }

  launchPasswordsApp({ searchUrl, newPasswordUrl, totpUri, totpPageUrl } = {}) {
    if (!this.port) throw new Error("not connected");
    const msg = { cmd: Command.LAUNCH_PASSWORDS_APP };
    if (totpUri) {
      if (!this.canSetUpTotp) throw new Error("this helper cant set up verification codes");
      msg.setUpTOTPURI = totpUri;
      if (totpPageUrl) msg.setUpTOTPPageURL = totpPageUrl;
    } else if (newPasswordUrl) {
      if (!this.canOpenPasswordsAppToNewPasswordSheet) throw new Error("this helper cant open the new-password sheet");
      msg.newPasswordWithSuggestedURL = newPasswordUrl;
    } else if (searchUrl) {
      msg.searchQueryURL = searchUrl;
    }
    this.port.postMessage(msg);
  }

  disconnect() {
    if (!this.port) return;
    try {
      this.port.postMessage({ cmd: Command.END });
    } catch (_) {}
    this._reset(new Error("Passwords locked. Unlock and try again."));
  }
}
