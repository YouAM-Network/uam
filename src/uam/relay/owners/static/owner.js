// UAM owner page. Spec P2 §3.2; rules: docs/design/owner-page/DESIGN.md.
//
// Before a passkey signs anything, the page works out the sentence itself
// from the key log entry and recomputes the challenge (the same as
// uam.protocol.keylog and webauthn.approval_challenge). If either differs
// from what the relay sent, it stops. Text goes into the page only through
// textContent; this script never writes markup.

const TYPE = "UamOwnerKeys";
const HASH = /^[A-Za-z0-9_-]{43}$/;
const LABEL = /^[\x20\x21\x23-\x7e]{1,64}$/; // the relay's rule: printable ASCII, no '"'
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const APPROVAL_MS = 290_000; // the relay's challenges last 5 minutes

// ---------------------------------------------------------------- checks

export function b64u(bytes) {
  let text = "";
  for (const b of new Uint8Array(bytes)) text += String.fromCharCode(b);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64u(text) {
  const raw = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const quoted = (keys) => keys.map((k) => `"${k.label}"`).join(", ");

/** The sentence an owner signs for a key log entry (keylog.screen_for). */
export function screenFor(body, previous) {
  if (previous === null) {
    const noun = body.keys.length === 1 ? "passkey" : "passkeys";
    return `Make ${quoted(body.keys)} the first ${noun} of your UAM owner account on ${body.owner.relay}.`;
  }
  const before = new Map(previous.keys.map((k) => [k.id, k]));
  const lines = [];
  const added = body.keys.filter((k) => !before.has(k.id));
  if (added.length) {
    const noun = added.length === 1 ? "passkey" : "passkeys";
    lines.push(`Add the ${noun} ${quoted(added)} to your UAM owner account.`);
  }
  for (const item of body.removed ?? []) {
    const label = before.has(item.id) ? quoted([before.get(item.id)]) : item.id;
    lines.push(item.reason === "compromised"
      ? `Remove the passkey ${label} from your UAM owner account as compromised.`
      : `Remove the passkey ${label} from your UAM owner account.`);
  }
  return lines.join(" ");
}

/** An entry's hash from its canonical text (signed.object_hash). */
export async function entryHash(text) {
  return b64u(await sha256(`UAM-${TYPE}-v1\n${text}`));
}

/** The challenge that signs one entry as shown (keylog.entry_challenge). */
export async function approvalChallenge(hash, screen) {
  if (!HASH.test(hash)) throw new Error("refused: not a hash");
  const set = `{"screen":"${hex(await sha256(screen))}","set":[{"h":"${hash}","t":"${TYPE}"}]}`;
  return b64u(await sha256(`UAM-APPROVAL-v1\n${set}`));
}

/**
 * Checks what the relay asks a passkey to sign. *answer* is register/finish's
 * {body, hash, screen, challenge}; *previous* is the entry before it
 * ({body, hash}, from the public key log) or null. Returns the sentence to
 * show, worked out here; throws if anything differs.
 */
export async function checkApproval(answer, previous) {
  const refuse = (why) => { throw new Error(`refused: ${why}`); };
  let body;
  try { body = JSON.parse(answer.body); } catch { refuse("the entry isn't JSON"); }
  if (!body || body.type !== TYPE || !Number.isInteger(body.seq) || !Array.isArray(body.keys)) {
    refuse("not a key log entry");
  }
  const hash = await entryHash(answer.body);
  if (hash !== answer.hash) refuse("the hash isn't the entry's");
  let prev = null;
  if (body.seq > 0) {
    if (!previous || previous.hash !== body.prev) refuse("the entry before isn't the one it follows");
    if (await entryHash(previous.body) !== previous.hash) refuse("the entry before isn't its hash");
    prev = JSON.parse(previous.body);
    if (prev.type !== TYPE || prev.seq !== body.seq - 1) refuse("the entry before is out of order");
  }
  const screen = screenFor(body, prev);
  if (screen !== answer.screen) refuse("the relay's words aren't the entry's");
  if (await approvalChallenge(hash, screen) !== answer.challenge) refuse("the challenge isn't these words");
  return screen;
}

export const validLabel = (label) => LABEL.test(label);

/** "9 Nov 2026" from the relay's UTC timestamp. */
export function addedOn(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T/.exec(iso);
  return m ? `${Number(m[3])} ${MONTHS[Number(m[2]) - 1]} ${m[1]}` : "";
}

// ---------------------------------------------------------------- the page

const $ = (id) => document.getElementById(id);
const AGAIN = "Something went wrong. Check your connection and try again.";

class Stop extends Error {} // already handled (signed out); nothing more to say

const state = { me: null, email: "", pending: null, opener: null, busy: false, timer: 0 };

async function api(path, body) {
  const init = body === undefined
    ? { method: "GET", credentials: "same-origin" }
    : { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body) };
  const resp = await fetch(path, init);
  let data = {};
  try { data = (await resp.json()) ?? {}; } catch { /* no body */ }
  if (resp.status === 401 && path !== "/api/owner/me") {
    showSignIn();
    throw new Stop();
  }
  return { status: resp.status, ok: resp.ok, data };
}

function say(el, text) {
  el.textContent = text;
  el.hidden = !text;
}

function problem(input, el, text) {
  say(el, text);
  if (text) {
    input.setAttribute("aria-invalid", "true");
    input.setAttribute("aria-describedby", el.id);
    input.focus();
  } else {
    input.removeAttribute("aria-invalid");
    input.removeAttribute("aria-describedby");
  }
}

function busy(button, text) {
  const was = button.textContent;
  button.disabled = true;
  button.textContent = text;
  return () => { button.disabled = false; button.textContent = was; };
}

function on(el, event, problemEl, handler) {
  el.addEventListener(event, async (e) => {
    if (event === "submit") e.preventDefault();
    try {
      await handler();
    } catch (err) {
      if (err instanceof Stop) return;
      console.error(err);
      say(problemEl, AGAIN);
    }
  });
}

function show(screen) {
  const screens = { loading: $("loading"), signin: $("signin"), code: $("code"), account: $("account") };
  for (const [name, el] of Object.entries(screens)) el.hidden = name !== screen;
}

// ---- signing in

function showSignIn() {
  closeSheet(false);
  state.me = null;
  show("signin");
}

async function sendCode() {
  const input = $("email");
  const email = input.value.trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return problem(input, $("email-problem"), "Enter an email address, like name@example.com.");
  }
  problem(input, $("email-problem"), "");
  const done = busy($("email-send"), "Sending…");
  let r;
  try { r = await api("/api/owner/sign-in/start", { email }); } finally { done(); }
  if (r.status === 422) return problem(input, $("email-problem"), "That doesn't look like an email address.");
  if (!r.ok) throw new Error(`sign-in start: ${r.status}`);
  state.email = email;
  $("code-email").textContent = email;
  $("code-input").value = "";
  problem($("code-input"), $("code-problem"), "");
  say($("code-status"), "");
  show("code");
  $("code-input").focus();
}

async function checkCode() {
  const input = $("code-input");
  const code = input.value.replace(/\s/g, "");
  if (!/^[0-9]{6}$/.test(code)) return problem(input, $("code-problem"), "Enter the 6 digits from the email.");
  const done = busy($("code-send"), "Signing in…");
  let r;
  try { r = await api("/api/owner/sign-in/finish", { email: state.email, code }); } finally { done(); }
  if (r.status === 400 || r.status === 422) {
    return problem(input, $("code-problem"), "That code didn't work. Check it, or ask for a new one.");
  }
  if (!r.ok) throw new Error(`sign-in finish: ${r.status}`);
  problem(input, $("code-problem"), "");
  await loadAccount();
  ($("first").hidden ? $("keys-title") : $("first-title")).focus();
}

async function resend() {
  const r = await api("/api/owner/sign-in/start", { email: state.email });
  if (!r.ok) throw new Error(`sign-in start: ${r.status}`);
  say($("code-status"), "We sent a new code. Only the newest one works.");
}

function otherEmail() {
  show("signin");
  $("email").focus();
}

async function signOut() {
  await api("/api/owner/sign-out", {});
  $("email").value = "";
  showSignIn();
  $("signin-title").focus();
}

// ---- the account

function passkeyItem(p) {
  const li = document.createElement("li");
  const name = document.createElement("span");
  name.className = "name";
  name.textContent = p.label;
  const meta = document.createElement("span");
  meta.className = "meta";
  meta.textContent = `${p.backupEligible ? "Synced" : "This device only"} · `;
  const when = document.createElement("span");
  when.className = "when";
  when.textContent = `added ${addedOn(p.createdAt)}`;
  meta.append(when);
  li.append(name, meta);
  return li;
}

async function loadAccount() {
  const me = await api("/api/owner/me");
  if (!me.ok) return showSignIn();
  state.me = me.data;
  $("who-email").textContent = me.data.email;
  const first = !me.data.owner_id;
  let keys = [];
  if (!first) keys = (await api("/api/owner/passkeys")).data.passkeys ?? [];
  $("first").hidden = !first;
  $("keys").hidden = first;
  $("owner-section").hidden = first;
  $("owner-id").textContent = me.data.owner_id ?? "";
  $("key-list").replaceChildren(...keys.map(passkeyItem));
  show("account");
}

// ---- adding a passkey: create, then approve the entry that adds it

async function previousEntry(answer) {
  const seq = JSON.parse(answer.body).seq;
  if (seq === 0) return null;
  const owner = encodeURIComponent(state.me.owner_id ?? "");
  const r = await api(`/api/owner/keys/${owner}?since=${seq - 1}`);
  const entry = (r.data.entries ?? []).find((e) => e.seq === seq - 1);
  return entry ? { body: entry.body, hash: entry.hash } : null;
}

async function createPasskey(input, problemEl, button) {
  const label = input.value.trim();
  if (!label) return problem(input, problemEl, "Give it a name, like the device it's on.");
  if (label.length > 64) return problem(input, problemEl, "Use 64 characters or fewer.");
  if (!validLabel(label)) {
    return problem(input, problemEl, "Use plain letters, numbers and punctuation, without quotation marks.");
  }
  if (!window.PublicKeyCredential || !navigator.credentials) {
    return problem(input, problemEl, "This browser can't make passkeys. Try a recent Safari, Chrome, Edge or Firefox.");
  }
  problem(input, problemEl, "");
  const done = busy(button, "Waiting for your device…");
  try {
    const start = await api("/api/owner/passkeys/register/start", {});
    if (!start.ok) return problem(input, problemEl, start.data.detail ?? AGAIN);
    const o = start.data;
    let made;
    try {
      made = await navigator.credentials.create({ publicKey: {
        rp: o.rp,
        user: { id: unb64u(o.user.id), name: o.user.name, displayName: o.user.displayName },
        challenge: unb64u(o.challenge),
        pubKeyCredParams: o.pubKeyCredParams,
        authenticatorSelection: o.authenticatorSelection,
        attestation: o.attestation,
        timeout: o.timeout,
        excludeCredentials: o.excludeCredentials.map((c) => ({ type: c.type, id: unb64u(c.id) })),
      } });
    } catch (err) {
      if (err.name === "InvalidStateError") {
        return problem(input, problemEl, "This device already has a passkey for your account.");
      }
      if (err.name === "NotAllowedError" || err.name === "AbortError") return; // they said no
      throw err;
    }
    const finish = await api("/api/owner/passkeys/register/finish", {
      attestationObject: b64u(made.response.attestationObject),
      clientDataJSON: b64u(made.response.clientDataJSON),
      label,
    });
    if (!finish.ok) return problem(input, problemEl, finish.data.detail ?? AGAIN);
    let screen;
    try {
      screen = await checkApproval(finish.data, await previousEntry(finish.data));
    } catch (err) {
      console.error(err);
      forget({ answer: finish.data, created: made.rawId });
      return problem(input, problemEl,
        "This page stopped: what your passkey would sign didn't match what it would show. Nothing was signed.");
    }
    state.pending = { answer: finish.data, created: made.rawId, label, first: !state.me.owner_id };
    openApprove(screen, button);
  } finally {
    done();
  }
}

function forget(pending) {
  // The passkey was made on the device but never added: ask the device to drop it.
  const signal = window.PublicKeyCredential?.signalUnknownCredential;
  if (!pending?.created || !signal) return;
  signal.call(PublicKeyCredential, {
    rpId: pending.answer.rpId, credentialId: b64u(pending.created),
  }).catch(() => {});
}

function openApprove(screen, opener) {
  $("approve-text").textContent = screen;
  say($("approve-problem"), "");
  openSheet($("sheet-approve"), opener, $("approve-title"));
  clearTimeout(state.timer);
  state.timer = setTimeout(() => { if (!state.busy) stopped("slow"); }, APPROVAL_MS);
}

async function approve() {
  const p = state.pending;
  if (!p) return;
  const done = busy($("approve"), "Waiting for your device…");
  state.busy = true;
  try {
    let got;
    try {
      got = await navigator.credentials.get({ publicKey: {
        challenge: unb64u(p.answer.challenge),
        rpId: p.answer.rpId,
        allowCredentials: p.answer.allowCredentials.map((id) => ({ type: "public-key", id: unb64u(id) })),
        userVerification: "required",
        timeout: APPROVAL_MS,
      } });
    } catch (err) {
      if (err.name === "NotAllowedError" || err.name === "AbortError") return; // they can try again
      throw err;
    }
    const r = await api("/api/owner/keys/sign", {
      credentialId: b64u(got.rawId),
      authenticatorData: b64u(got.response.authenticatorData),
      clientDataJSON: b64u(got.response.clientDataJSON),
      signature: b64u(got.response.signature),
    });
    if (r.ok) return added(p);
    stopped(r.data.error === "bad_challenge" ? "slow" : r.data.error === "log_moved" ? "moved" : "refused",
      r.data.detail);
  } finally {
    state.busy = false;
    done();
  }
}

async function added(p) {
  state.pending = null;
  closeSheet(false);
  await loadAccount();
  say($("keys-status"), `Added "${p.label}".`);
  $("keys-title").focus();
}

function stopped(why, detail) {
  clearTimeout(state.timer);
  forget(state.pending);
  const words = {
    slow: ["That took too long", "The request expired after 5 minutes, so nothing was changed."],
    moved: ["Your passkeys changed", "Another change was made while this one waited, so nothing was changed."],
    refused: ["That didn't work", `${detail ?? "Your passkey couldn't approve this."} Nothing was changed.`],
  }[why];
  $("stopped-title").textContent = words[0];
  $("stopped-text").textContent = words[1];
  openSheet($("sheet-stopped"), null, $("stopped-title"));
}

function restart() {
  const first = state.pending?.first ?? !state.me?.owner_id;
  state.pending = null;
  closeSheet(false);
  if (first) {
    $("first-name").focus();
  } else {
    openName();
  }
}

function cancelApproval() {
  forget(state.pending);
  state.pending = null;
  closeSheet(true);
}

// ---- sheets

function openSheet(sheet, opener, focus) {
  for (const s of [$("sheet-name"), $("sheet-approve"), $("sheet-stopped")]) s.hidden = s !== sheet;
  $("scrim").hidden = false;
  $("account").inert = true;
  if (opener && !state.opener) state.opener = opener; // the first opener is where focus returns
  focus.focus();
}

function closeSheet(returnFocus) {
  clearTimeout(state.timer);
  $("scrim").hidden = true;
  $("account").inert = false;
  const opener = state.opener;
  state.opener = null;
  if (!returnFocus) return;
  if (opener && opener.offsetParent !== null) {
    opener.focus();
  } else {
    ($("keys").hidden ? $("first-title") : $("keys-title")).focus();
  }
}

function openName() {
  const input = $("name-input");
  input.value = "";
  problem(input, $("name-problem"), "");
  openSheet($("sheet-name"), $("add"), input);
}

function escape(e) {
  if (e.key !== "Escape" || $("scrim").hidden || state.busy) return;
  e.preventDefault();
  if (!$("sheet-approve").hidden) return cancelApproval();
  state.pending = null;
  closeSheet(true);
}

// ---- start

function start() {
  on($("email-form"), "submit", $("email-problem"), sendCode);
  on($("code-form"), "submit", $("code-problem"), checkCode);
  on($("resend"), "click", $("code-status"), resend);
  on($("other-email"), "click", $("code-status"), otherEmail);
  on($("sign-out"), "click", $("keys-status"), signOut);
  on($("first-form"), "submit", $("first-problem"),
    () => createPasskey($("first-name"), $("first-problem"), $("first-create")));
  on($("add"), "click", $("keys-status"), openName);
  on($("name-form"), "submit", $("name-problem"),
    () => createPasskey($("name-input"), $("name-problem"), $("name-create")));
  on($("name-cancel"), "click", $("name-problem"), () => closeSheet(true));
  on($("approve"), "click", $("approve-problem"), approve);
  on($("approve-cancel"), "click", $("approve-problem"), cancelApproval);
  on($("restart"), "click", $("stopped-text"), restart);
  on($("stopped-close"), "click", $("stopped-text"), () => { state.pending = null; closeSheet(true); });
  document.addEventListener("keydown", escape);
  loadAccount().catch((err) => {
    if (err instanceof Stop) return;
    console.error(err);
    showSignIn();
  });
}

if (typeof document !== "undefined") start();
