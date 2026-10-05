const views = {
  nohelper: document.getElementById("view-nohelper"),
  pin: document.getElementById("view-pin"),
  connecting: document.getElementById("view-connecting"),
  unlocked: document.getElementById("view-unlocked"),
};
const dot = document.getElementById("dot");
const pinInput = document.getElementById("pin");
const pinError = document.getElementById("pin-error");
const pinBoxes = [...document.querySelectorAll(".code-boxes span")];
const refreshBtn = document.getElementById("refresh");

function show(name) {
  for (const [k, el] of Object.entries(views)) el.hidden = k !== name;
}

const pmToggle = document.getElementById("pm-toggle");
const pmNote = document.getElementById("pm-note");

function renderPmToggle() {
  const pref = chrome.privacy?.services?.passwordSavingEnabled;
  const row = document.getElementById("pm-row");
  if (!pref?.get) return;
  pref.get({}, (d) => {
    if (chrome.runtime.lastError || !d) return;
    row.hidden = false;
    pmToggle.checked = d.value === false;
    const controllable =
      d.levelOfControl === "controllable_by_this_extension" ||
      d.levelOfControl === "controlled_by_this_extension";
    pmToggle.disabled = !controllable;
    pmNote.textContent = controllable
      ? ""
      : d.levelOfControl === "controlled_by_other_extensions"
        ? "controlled by another extension"
        : "controlled by browser policy";
  });
}

pmToggle.addEventListener("change", () => {
  const pref = chrome.privacy?.services?.passwordSavingEnabled;
  if (!pref) return;
  const on = pmToggle.checked;
  chrome.storage?.local?.set({ suppressSaveBubble: on });
  // read back after writing, the browser can silently refuse
  const verify = () =>
    pref.get({}, (d) => {
      renderPmToggle();
      if (on && d && d.value !== false) {
        pmNote.textContent = "browser refused it - flip it in password settings below";
      }
    });
  if (on) pref.set({ value: false }, verify);
  else pref.clear({}, verify);
});

renderPmToggle();

// a user defaults write isnt a forced policy, only a config profile approved once in System Settings is
const policyToggle = document.getElementById("policy-toggle");
const policyNote = document.getElementById("policy-note");

function policyMsg(action) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage("com.openpasswords.policy", { action }, (resp) => {
        if (chrome.runtime.lastError) resolve({ error: chrome.runtime.lastError.message });
        else resolve(resp || { error: "no reply" });
      });
    } catch (e) {
      resolve({ error: String(e) });
    }
  });
}

async function renderPolicyToggle() {
  const r = await policyMsg("get");
  if (r.error || !r.ok) {
    policyToggle.disabled = true;
    policyNote.textContent = "needs the policy helper - run native/install.sh";
    return;
  }
  policyToggle.disabled = false;
  policyToggle.checked = !!r.hidden;
  policyNote.textContent = "";
}

policyToggle.addEventListener("change", async () => {
  const on = policyToggle.checked;
  policyToggle.disabled = true;
  const r = await policyMsg(on ? "set" : "clear");
  policyToggle.disabled = false;
  if (r.error || !r.ok) {
    policyNote.textContent = "helper failed - run native/install.sh";
    policyToggle.checked = !on;
    return;
  }
  // the profile only sticks once approved, reflect the real forced state
  policyToggle.checked = !!r.hidden;
  if (on && !r.hidden) policyNote.textContent = "approve the profile in System Settings, then reopen this popup";
  else if (!on && r.hidden) policyNote.textContent = "remove the profile in System Settings, then reopen this popup";
  else policyNote.textContent = "";
});

renderPolicyToggle();

// credit-card autofill stays untouched so google pay keeps working
const afToggle = document.getElementById("af-toggle");
const afNote = document.getElementById("af-note");

function renderAfToggle() {
  const pref = chrome.privacy?.services?.autofillAddressEnabled;
  const row = document.getElementById("af-row");
  if (!pref?.get) return;
  pref.get({}, (d) => {
    if (chrome.runtime.lastError || !d) return;
    row.hidden = false;
    afToggle.checked = d.value === false;
    const controllable =
      d.levelOfControl === "controllable_by_this_extension" ||
      d.levelOfControl === "controlled_by_this_extension";
    afToggle.disabled = !controllable;
    afNote.textContent = controllable ? "" : "controlled elsewhere";
  });
}

afToggle.addEventListener("change", () => {
  const pref = chrome.privacy?.services?.autofillAddressEnabled;
  if (!pref) return;
  const on = afToggle.checked;
  chrome.storage?.local?.set({ suppressAddressAutofill: on });
  const verify = () =>
    pref.get({}, (d) => {
      renderAfToggle();
      if (on && d && d.value !== false) {
        afNote.textContent = "browser refused it - flip it in autofill settings";
      }
    });
  if (on) pref.set({ value: false }, verify);
  else pref.clear({}, verify);
});

renderAfToggle();

const pkToggle = document.getElementById("pk-toggle");
chrome.storage?.local?.get({ hidePasskeys: false }, (d) => {
  pkToggle.checked = !!d.hidePasskeys;
});
pkToggle.addEventListener("change", () => {
  chrome.storage?.local?.set({ hidePasskeys: pkToggle.checked });
});

// off by default, needs the browser allowed to automate System Events and macOS asks the first time
const autoPairToggle = document.getElementById("autopair-toggle");
const autoPairNote = document.getElementById("autopair-note");
chrome.storage?.local?.get({ autoPair: false }, (d) => {
  autoPairToggle.checked = !!d.autoPair;
});
autoPairToggle.addEventListener("change", async () => {
  const on = autoPairToggle.checked;
  chrome.storage?.local?.set({ autoPair: on });
  autoPairNote.textContent = "";
  if (!on) return;
  autoPairNote.textContent = "checking…";
  const r = await send({ type: "autoPairCheck" });
  if (r?.ok) {
    autoPairNote.textContent = "on - the next code your Mac shows gets entered for you";
  } else if (/not found|forbidden|host/i.test(r?.error || "")) {
    autoPairNote.textContent = "needs the reader helper - run native/install.sh, then restart the browser";
  } else {
    autoPairNote.textContent = r?.error || "the reader could not reach System Events";
  }
});

function renderAutoPairError(err) {
  if (!autoPairToggle.checked || !err) return;
  autoPairNote.textContent = `last attempt: ${err}`;
}

function setDot(state) {
  dot.className = "dot";
  if (state === "unlocked") dot.classList.add("ok");
  else if (state === "needs_pin") dot.classList.add("warn");
  else if (state === "no_helper") dot.classList.add("err");
  document.getElementById("status-text").textContent = {
    unlocked: "Connected to Apple Passwords",
    needs_pin: "Apple Passwords is locked",
    no_helper: "Apple Passwords is unavailable",
  }[state] || "Connecting to Apple Passwords";
}

function send(msg) {
  return new Promise((resolve) => chrome.runtime.sendMessage(msg, (response) => {
    const error = chrome.runtime.lastError;
    resolve(error ? { ok: false, error: error.message } : response);
  }));
}

let pageTarget = null;
let pageError = "";
let targetRequest;
async function getPageTarget() {
  if (!targetRequest) targetRequest = send({ type: "getPageTarget" }).then((r) => {
    pageTarget = r?.ok ? r.target : null;
    pageError = r?.error || "Reload this page to enable Open Passwords.";
    return pageTarget;
  });
  return targetRequest;
}
function pageMessage(message, target = pageTarget) {
  return send({ ...message, target });
}

let lastState = "disconnected";
let viewRevision = 0;

async function render(state) {
  const revision = ++viewRevision;
  lastState = state;
  if (state !== "unlocked") {
    document.getElementById("logins").replaceChildren();
    document.getElementById("codes").replaceChildren();
    pageTotpUri = null;
  }
  document.getElementById("lock").hidden = state !== "unlocked";
  if (state !== "needs_pin") setPin("");
  setDot(state);
  refreshBtn.hidden = state !== "unlocked" && state !== "needs_pin";
  if (state === "no_helper") return show("nohelper");
  if (state === "disconnected") return show("connecting");
  if (state === "needs_pin") {
    show("pin");
    renderPinBoxes();
    pinInput.focus();
    return;
  }
  if (state === "unlocked") {
    await getPageTarget();
    if (revision !== viewRevision) return;
    await renderLogins(revision);
    if (revision !== viewRevision) return;
    show("unlocked");
    renderCodes(revision);
    renderAppLinks(revision);
    const search = document.getElementById("search");
    if (search.offsetParent) search.focus();
    else document.querySelector("#logins button")?.focus();
    return;
  }
  // unknown state must never leave every view hidden (blank popup)
  show("connecting");
}

function glyph(className) {
  const span = document.createElement("span");
  span.className = className;
  span.setAttribute("aria-hidden", "true");
  return span;
}

function codeGlyph() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "glyph code-glyph");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", "../icons/ui.svg#code");
  svg.appendChild(use);
  return svg;
}

function itemText(title, subtitle) {
  const text = document.createElement("span");
  text.className = "item-text";
  const main = document.createElement("span");
  main.textContent = title;
  text.appendChild(main);
  if (subtitle) {
    const sub = document.createElement("span");
    sub.className = "item-sub";
    sub.textContent = subtitle;
    text.appendChild(sub);
  }
  return text;
}

async function renderLogins(revision = viewRevision) {
  const target = pageTarget;
  const host = pageTarget ? new URL(pageTarget.url).host : "";
  const list = document.getElementById("logins");
  const none = document.getElementById("nologins");
  list.innerHTML = "";
  none.hidden = true;
  none.textContent = "No saved passwords for this site.";
  document.getElementById("search-empty").hidden = true;
  document.querySelector(".search-field").hidden = true;

  const res = target ? await pageMessage({ type: "getLogins" }, target) : { ok: false, error: pageError };
  if (revision !== viewRevision || target !== pageTarget) return;
  if (!res?.ok) {
    none.hidden = false;
    none.textContent = res?.error ?? "Couldn't load logins.";
    return;
  }
  if (!res.logins.length) {
    none.hidden = false;
    return;
  }
  document.querySelector(".search-field").hidden = res.logins.length < 6;
  for (const login of res.logins) {
    const li = document.createElement("li");
    li.dataset.search = (login.username || "").toLowerCase();
    const name = login.username || "(no username)";
    const fill = document.createElement("button");
    fill.className = "menu-item";
    fill.title = name;
    fill.setAttribute("aria-label", `Fill password for ${name}`);
    fill.addEventListener("click", async () => {
      fill.disabled = true;
      const r = await pageMessage({ type: "fillOnPage", loginName: login }, target);
      if (r?.ok && r.filled) window.close();
      else { fill.disabled = false; flashNote(r?.error || "Focus a login field and try again."); }
    });
    fill.append(glyph("key-glyph"), itemText(name, host));
    li.appendChild(fill);
    list.appendChild(li);
  }
  filterLogins();
}

async function renderCodes(revision = viewRevision) {
  const target = pageTarget;
  const list = document.getElementById("codes");
  list.innerHTML = "";
  list.hidden = true;
  if (!pageTarget) return;
  const res = await pageMessage({ type: "getOneTimeCodes" }, target);
  if (revision !== viewRevision || target !== pageTarget) return;
  if (!res?.ok || !res.rows?.length) return;
  for (const row of res.rows) {
    const li = document.createElement("li");
    const label = row.source === "totp" ? row.domain || "Verification Code" : "Code from Messages";
    const fill = document.createElement("button");
    fill.className = "menu-item";
    fill.append(codeGlyph(), itemText(label, row.username));
    fill.setAttribute("aria-label", `Fill verification code for ${row.username || row.domain || "this site"}`);
    fill.addEventListener("click", async () => {
      fill.disabled = true;
      const r = await pageMessage({ type: "fillOneTimeCode", id: row.id }, target);
      if (revision !== viewRevision) return;
      if (r?.ok && r.filled) return window.close();
      if (r?.ok && r.code) {
        const badge = codeBadge(r.code);
        fill.classList.add("showing-code");
        fill.appendChild(badge);
        setTimeout(() => { badge.textContent = "Expired"; }, 30_000);
        return;
      }
      fill.disabled = false;
      flashNote(r?.error ? `Couldn't read the code: ${r.error}` : "Couldn't read the code");
    });
    li.appendChild(fill);
    list.appendChild(li);
  }
  list.hidden = false;
}

function codeBadge(code) {
  const b = document.createElement("span");
  b.className = "code-value";
  b.textContent = code;
  b.title = "Current code";
  return b;
}

let caps = {};
let pageTotpUri = null;
async function renderAppLinks(revision = viewRevision) {
  const target = pageTarget;
  document.getElementById("new-login").hidden = !caps.newPasswordSheet;
  const totpBtn = document.getElementById("setup-totp");
  totpBtn.hidden = true;
  pageTotpUri = null;
  if (!caps.setUpTotp) return;
  try {
    if (!pageTarget) return;
    const r = await chrome.tabs.sendMessage(pageTarget.tabId, { type: "findTotpUri" }, { documentId: pageTarget.documentId });
    if (revision !== viewRevision || target !== pageTarget) return;
    const uri = r?.uris?.[0];
    if (!uri) return;
    pageTotpUri = uri;
    totpBtn.hidden = false;
  } catch (_) {}
}

document.getElementById("open-app").addEventListener("click", async () => {
  await pageMessage({ type: "openPasswordsApp", mode: "search" });
  window.close();
});
document.getElementById("new-login").addEventListener("click", async () => {
  await pageMessage({ type: "openPasswordsApp", mode: "new" });
  window.close();
});
document.getElementById("setup-totp").addEventListener("click", async () => {
  if (!pageTotpUri) return;
  await pageMessage({ type: "openPasswordsApp", mode: "totp", uri: pageTotpUri });
  window.close();
});

function setPin(value) {
  pinInput.value = value;
  renderPinBoxes();
}

function renderPinBoxes() {
  const pin = pinInput.value;
  pinBoxes.forEach((box, i) => {
    box.textContent = pin[i] ?? "";
    box.classList.toggle("current", i === Math.min(pin.length, 5));
  });
}

async function verifyPin() {
  pinError.hidden = true;
  const pin = pinInput.value.trim();
  if (!/^\d{6}$/.test(pin) || pinInput.disabled) return;
  pinInput.disabled = true;
  const res = await send({ type: "verifyPin", pin });
  setPin("");
  pinInput.disabled = false;
  if (res?.ok) render(res.state);
  else {
    // a failed attempt spends the code, so the background put a fresh one on the Mac
    const base = res?.error ?? "Verification failed.";
    pinError.textContent = res?.newCode ? `${base} - enter the new code on your Mac` : base;
    pinError.hidden = false;
    pinInput.focus();
  }
}

pinInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") verifyPin();
});
pinInput.addEventListener("input", () => {
  setPin(pinInput.value.replace(/\D/g, "").slice(0, 6));
  if (pinInput.value.length === 6) verifyPin();
});

let noteTimer = null;
function flashNote(text) {
  const el = document.getElementById("refresh-note");
  el.textContent = text;
  el.hidden = false;
  clearTimeout(noteTimer);
  noteTimer = setTimeout(() => (el.hidden = true), 2500);
}

refreshBtn.addEventListener("click", async () => {
  refreshBtn.disabled = true;
  refreshBtn.classList.add("spinning");
  if (lastState === "needs_pin") {
    pinError.hidden = true;
    setPin("");
    const res = await send({ type: "requestChallenge" });
    if (res?.ok) render(res.state);
    else {
      pinError.textContent = res?.error ?? "Couldn't request a code.";
      pinError.hidden = false;
    }
  } else {
    const revision = ++viewRevision;
    await send({ type: "clearCache" });
    targetRequest = null;
    await getPageTarget();
    if (revision === viewRevision) {
      await renderLogins(revision);
      await renderCodes(revision);
      renderAppLinks(revision);
      if (revision === viewRevision) flashNote("Passwords refreshed");
    }
  }
  refreshBtn.classList.remove("spinning");
  refreshBtn.disabled = false;
});

document.getElementById("newcode").addEventListener("click", async () => {
  pinError.hidden = true;
  const res = await send({ type: "requestChallenge" });
  if (res?.ok) render(res.state);
  else {
    pinError.textContent = res?.error ?? "Couldn't request a code.";
    pinError.hidden = false;
  }
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "state") {
    render(msg.state);
    // capabilities arrive with the hello, which precedes the first state change
    send({ type: "getState" }).then((r) => {
      caps = r?.caps || caps;
    });
  }
});

(async () => {
  const res = await send({ type: "getState" });
  caps = res?.caps || {};
  renderAutoPairError(res?.autoPairError);
  let state = res?.state ?? "disconnected";
  if (state === "needs_pin") {
    // never on top of a code thats already showing, a second prompt kills the first code
    const ch = await send({ type: "requestChallenge", ifNeeded: true });
    state = ch?.state ?? state;
  }
  render(state);
})();

const searchInput = document.getElementById("search");
function filterLogins() {
  const query = searchInput.value.trim().toLowerCase();
  const rows = [...document.querySelectorAll("#logins li")];
  for (const row of rows) row.hidden = !row.dataset.search.includes(query);
  document.getElementById("search-empty").hidden = !rows.length || rows.some((row) => !row.hidden);
}
searchInput.addEventListener("input", filterLogins);
document.addEventListener("keydown", (event) => {
  if (lastState !== "unlocked" || !["ArrowDown", "ArrowUp", "Enter"].includes(event.key)) return;
  const active = document.activeElement;
  if (active !== searchInput && !active.closest("#logins, #codes")) return;
  const buttons = [...document.querySelectorAll("#logins li:not([hidden]) button, #codes button")].filter((b) => !b.disabled);
  if (!buttons.length) return;
  if (event.key === "Enter") {
    if (active !== searchInput) return; // native button activation handles Enter
    event.preventDefault();
    buttons.find((button) => button.closest("#logins"))?.click();
    return;
  }
  event.preventDefault();
  const index = buttons.indexOf(active);
  const next = event.key === "ArrowDown" ? (index + 1) % buttons.length : (index < 0 ? buttons.length - 1 : (index - 1 + buttons.length) % buttons.length);
  buttons[next].focus();
});
document.getElementById("lock").addEventListener("click", async () => {
  await send({ type: "disconnect" });
  window.close();
});
