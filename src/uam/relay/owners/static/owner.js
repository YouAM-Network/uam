// YouAM account page (the owner page). Spec P2 §3.2; rules: docs/design/owner-page/DESIGN.md.
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
    return `Make ${quoted(body.keys)} the first ${noun} of your YouAM account on ${body.owner.relay}.`;
  }
  const before = new Map(previous.keys.map((k) => [k.id, k]));
  const lines = [];
  const added = body.keys.filter((k) => !before.has(k.id));
  if (added.length) {
    const noun = added.length === 1 ? "passkey" : "passkeys";
    lines.push(`Add the ${noun} ${quoted(added)} to your YouAM account.`);
  }
  for (const item of body.removed ?? []) {
    const label = before.has(item.id) ? quoted([before.get(item.id)]) : item.id;
    lines.push(item.reason === "compromised"
      ? `Remove the passkey ${label} from your YouAM account as compromised.`
      : `Remove the passkey ${label} from your YouAM account.`);
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

// ---------------------------------------------------------------- links (P2d)
//
// The same rules as uam.protocol.links: the four words, the sentences an
// owner signs for a link, a set of links and an unlink, and their challenge.

const LINK = "UamOwnerLink";
const UNLINK = "UamOwnerUnlink";
// An address as the relay's schema allows it: nothing that could close the
// quotes around it in a sentence.
const ADDRESS = /^[a-z0-9_-]{1,64}::[a-z0-9.-]{1,253}$/;
const STAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):\d{2}Z$/;

/** An object's hash from its canonical text (signed.object_hash). */
export async function objectHash(type, text) {
  return b64u(await sha256(`UAM-${type}-v1\n${text}`));
}

/** The challenge one passkey signs to approve *items* ({t, h}) as *screen* shows them. */
export async function challengeFor(items, screen) {
  for (const { h } of items) if (!HASH.test(h)) throw new Error("refused: not a hash");
  const set = items.map(({ t, h }) => `{"h":"${h}","t":"${t}"}`).join(",");
  return b64u(await sha256(`UAM-APPROVAL-v1\n{"screen":"${hex(await sha256(screen))}","set":[${set}]}`));
}

/** The four words a person checks for an agent key (links.words_for). */
export async function wordsFor(agentKey) {
  const d = await sha256(`UAM-WORDS-v1\n${agentKey}`);
  let head = 0n;
  for (const b of d.slice(0, 6)) head = (head << 8n) | BigInt(b);
  head >>= 4n; // the first 44 bits: four words of 11
  return [3, 2, 1, 0].map((i) => WORDS[Number((head >> BigInt(11 * i)) & 2047n)]);
}

/** "13 Nov 2026 at 15:04 UTC". */
export function startsOn(iso) {
  const m = STAMP.exec(iso);
  if (!m) throw new Error("refused: not a time");
  return `${Number(m[3])} ${MONTHS[Number(m[2]) - 1]} ${m[1]} at ${m[4]}:${m[5]} UTC`;
}

function linkScreen(body, words) {
  let text = `Link the agent "${body.agent}" to your YouAM account. Its words are ${words.join(" ")}.`;
  if (body.via === "link") text += ` It starts on ${startsOn(body.effectiveAt)}.`;
  return text;
}

const byAgent = (a, b) => (a.body.agent < b.body.agent ? -1 : a.body.agent > b.body.agent ? 1 : 0);

function linksScreen(items) {
  if (items.length === 1) return linkScreen(items[0].body, items[0].words);
  const parts = items.map(({ body, words }) => {
    const starts = body.via === "link" ? `, starts ${startsOn(body.effectiveAt)}` : "";
    return `"${body.agent}" (${words.join(" ")}${starts})`;
  });
  return `Link ${items.length} agents to your YouAM account: ${parts.join(", ")}.`;
}

/**
 * Checks what the relay asks a passkey to sign for linking. *kind* is
 * "link" ({body, hash, screen, challenge}), "unlink" (the same) or "links"
 * ({bodies, hashes, screen, challenge}, in screen order). Returns the
 * sentence to show, worked out here; throws if anything differs.
 */
export async function checkLinkApproval(kind, answer, ownerId) {
  const refuse = (why) => { throw new Error(`refused: ${why}`); };
  const type = kind === "unlink" ? UNLINK : LINK;
  const texts = kind === "links" ? answer.bodies : [answer.body];
  const hashes = kind === "links" ? answer.hashes : [answer.hash];
  if (!Array.isArray(texts) || !texts.length || !Array.isArray(hashes) || hashes.length !== texts.length) {
    refuse("no bodies");
  }
  const items = [];
  for (const [i, text] of texts.entries()) {
    let body;
    try { body = JSON.parse(text); } catch { refuse("a body isn't JSON"); }
    if (!body || body.type !== type) refuse(`not a ${type}`);
    if (typeof body.agent !== "string" || !ADDRESS.test(body.agent)) refuse("not an agent address");
    if (typeof body.agentKey !== "string") refuse("no agent key");
    if (!body.owner || body.owner.ownerId !== ownerId) refuse("not for this account");
    if (await objectHash(type, text) !== hashes[i]) refuse("a hash isn't its body's");
    items.push({ body, hash: hashes[i], words: await wordsFor(body.agentKey) });
  }
  if (kind === "links") {
    const sorted = [...items].sort(byAgent);
    if (sorted.some((item, i) => item !== items[i])) refuse("the set isn't in order");
    if (new Set(items.map((x) => x.body.agent)).size !== items.length) refuse("an agent is there twice");
  } else if (items.length !== 1) {
    refuse("one body");
  }
  const screen = kind === "unlink"
    ? `Unlink the agent "${items[0].body.agent}" from your YouAM account.`
    : kind === "links" ? linksScreen(items) : linkScreen(items[0].body, items[0].words);
  if (screen !== answer.screen) refuse("the relay's words aren't the bodies'");
  const challenge = await challengeFor(items.map((x) => ({ t: type, h: x.hash })), screen);
  if (challenge !== answer.challenge) refuse("the challenge isn't these words");
  return screen;
}

// ---------------------------------------------------------------- contacts (P2e)
//
// The same rules as uam.protocol.contacts: the sentences an owner signs to
// invite someone, accept or confirm an invite, keep carried-over contacts
// and let more in. Each check also holds the bodies to what the person
// chose or was shown: their own account, the other person (by owner id),
// the invite's four words, the agents and the setting.

const INVITE = "UamInvite";
const REDEMPTION = "UamRedemption";
const GRANT = "UamContactGrant";
const POLICY = "UamAgentPolicy";
const SETTINGS = { open: "Let anyone message", contacts: "Let only your contacts message" };

/** Four words both owners read to each other to check one invite (contacts.invite_words). */
export async function inviteWords(inviteHash) {
  if (!HASH.test(inviteHash)) throw new Error("refused: not a hash");
  const d = await sha256(`UAM-SAS-v1\n${inviteHash}`);
  let head = 0n;
  for (const b of d.slice(0, 6)) head = (head << 8n) | BigInt(b);
  head >>= 4n;
  return [3, 2, 1, 0].map((i) => WORDS[Number((head >> BigInt(11 * i)) & 2047n)]);
}

/** A pre-approved invite's invitee, salted by its nonce (contacts.email_hash). */
async function emailHash(nonce, email) {
  return b64u(await sha256(`UAM-INVITE-EMAIL-v1\n${nonce}${email.trim().toLowerCase()}`));
}

async function secretHash(secret) {
  return b64u(await sha256(`UAM-INVITE-SECRET-v1\n${secret}`));
}

/** "9 Feb 2027" from a body's stamp. */
function dayOf(stamp) {
  const m = STAMP.exec(stamp ?? "");
  if (!m) throw new Error("refused: not a time");
  return `${Number(m[3])} ${MONTHS[Number(m[2]) - 1]} ${m[1]}`;
}

const sameList = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

function settingWords(body) {
  if (body.policy === "contacts" && body.sameOwner) return "Let your contacts and your own agents message";
  return SETTINGS[body.policy];
}

/**
 * Checks what the relay asks a passkey to sign for contacts and settings.
 * *answer* is a start route's {items: [{type, body, hash}], screen, challenge}.
 * *ctx* is what the page holds: {ownerId} and, by *kind*,
 *   invite:   {email} typed;
 *   redeem:   {inviter: {ownerId, email}, words} shown, {secret} from a link (null for a code);
 *   confirm:  {invitee: {ownerId, email}} shown;
 *   keep:     {agent, addresses} chosen;
 *   policies: {agents: [{agent, agentKey}], policy, sameOwner, fleet?} chosen.
 * Returns the sentence to show, worked out here; throws if anything differs.
 */
export async function checkContactApproval(kind, answer, ctx) {
  const refuse = (why) => { throw new Error(`refused: ${why}`); };
  const want = {
    invite: [INVITE, GRANT], redeem: [REDEMPTION, GRANT], confirm: [GRANT],
  }[kind];
  const items = Array.isArray(answer?.items) ? answer.items : refuse("no bodies");
  if (!items.length) refuse("no bodies");
  if (want && !sameList(items.map((x) => x.type), want)) refuse("not the bodies this needs");
  if (!want && !["keep", "policies"].includes(kind)) refuse("not a kind of approval");
  const each = kind === "keep" ? GRANT : POLICY;
  if (!want && items.some((x) => x.type !== each)) refuse("not the bodies this needs");
  const bodies = [];
  for (const { type, body: text, hash } of items) {
    let body;
    try { body = JSON.parse(text); } catch { refuse("a body isn't JSON"); }
    if (!body || body.type !== type) refuse(`not a ${type}`);
    if (await objectHash(type, text) !== hash) refuse("a hash isn't its body's");
    bodies.push(body);
  }
  const mine = (ref) => ref?.ownerId === ctx.ownerId || refuse("not for this account");
  const grant = (body, subject, locations) => {
    mine(body.issuerOwner);
    const d = body.authorization_details;
    if (!Array.isArray(d) || d.length !== 1 || d[0].type !== "uam_contact"
        || !sameList(d[0].actions ?? [], ["message"]) || !sameList(d[0].locations ?? [], locations)) {
      refuse("the grant lets in more than this says");
    }
    const s = body.credentialSubject ?? {};
    if (Object.keys(subject).some((k) => s[k] !== subject[k])) refuse("the grant is for someone else");
    return dayOf(body.validUntil);
  };
  let screen;
  if (kind === "invite") {
    const [invite, g] = bodies;
    mine(invite.inviter);
    if (invite.mode !== "preapproved" || invite.emailHash !== await emailHash(invite.nonce, ctx.email)) {
      refuse("the invite is for another email address");
    }
    const until = grant(g, { kind: "invitee", invite: items[0].hash }, ["shared"]);
    screen = `Invite ${ctx.email} to connect on YouAM. When they accept, their shared agents can message yours until ${until}.`;
  } else if (kind === "redeem" || kind === "confirm") {
    const other = kind === "redeem" ? ctx.inviter : ctx.invitee;
    const g = bodies[bodies.length - 1];
    if (g.credentialSubject?.kind !== "owner" || g.credentialSubject?.owner?.ownerId !== other.ownerId) {
      refuse("the grant is for someone else");
    }
    const until = grant(g, { kind: "owner" }, ["shared"]);
    if (kind === "redeem") {
      const r = bodies[0];
      mine(r.invitee);
      if (r.issuer !== g.issuer) refuse("signed by another passkey");
      if (!sameList(await inviteWords(r.invite), ctx.words)) refuse("not the invite you were shown");
      if (ctx.secret && r.secret !== ctx.secret) refuse("not the invite you opened");
    }
    screen = `Connect with ${other.email} on YouAM. Their shared agents can message yours until ${until}.`;
  } else if (kind === "keep") {
    if (!ADDRESS.test(ctx.agent)) refuse("not an agent address");
    const days = new Set();
    const names = [];
    for (const g of bodies) {
      if (g.credentialSubject?.kind !== "agent") refuse("a kept contact is an agent");
      days.add(grant(g, { kind: "agent" }, [ctx.agent]));
      names.push(g.credentialSubject.address);
    }
    names.sort();
    if (!sameList(names, [...ctx.addresses].sort()) || names.some((n) => !ADDRESS.test(n))) {
      refuse("not the contacts you chose");
    }
    if (days.size !== 1) refuse("the grants end on different days");
    const [until] = days;
    screen = names.length === 1
      ? `Let "${names[0]}" keep messaging "${ctx.agent}" until ${until}.`
      : `Let ${names.length} agents keep messaging "${ctx.agent}" until ${until}: ${names.map((n) => `"${n}"`).join(", ")}.`;
  } else {
    const chosen = new Map(ctx.agents.map((a) => [a.agent, a.agentKey]));
    for (const b of bodies) {
      mine(b.owner);
      if (!ADDRESS.test(b.agent) || chosen.get(b.agent) !== b.agentKey) refuse("not an agent you chose");
      if (b.policy !== ctx.policy || b.sameOwner !== ctx.sameOwner || !SETTINGS[b.policy]) {
        refuse("not the setting you chose");
      }
    }
    const names = bodies.map((b) => b.agent).sort();
    if (!sameList(names, [...chosen.keys()].sort())) refuse("not the agents you chose");
    const fleet = ctx.fleet ?? null;
    if (fleet !== null && (typeof fleet !== "string" || fleet.includes('"'))) refuse("not a fleet name");
    const who = settingWords(bodies[0]);
    if (names.length === 1 && fleet === null) {
      screen = `${who} "${names[0]}".`;
    } else {
      const count = `${names.length} agent${names.length === 1 ? "" : "s"}`;
      const which = fleet !== null ? `the ${count} in the "${fleet}" fleet` : `these ${count}`;
      screen = `${who} ${which}: ${names.map((n) => `"${n}"`).join(", ")}.`;
    }
  }
  if (screen !== answer.screen) refuse("the relay's words aren't the bodies'");
  const challenge = await challengeFor(items.map((x) => ({ t: x.type, h: x.hash })), screen);
  if (challenge !== answer.challenge) refuse("the challenge isn't these words");
  return screen;
}

/** "9 Nov 2026" from the relay's UTC timestamp. */
export function addedOn(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T/.exec(iso);
  return m ? `${Number(m[3])} ${MONTHS[Number(m[2]) - 1]} ${m[1]}` : "";
}

// ---------------------------------------------------------------- the page

const $ = (id) => document.getElementById(id);
const AGAIN = "Something went wrong. Check your connection and try again.";

class Stop extends Error {} // already handled (signed out); nothing more to say

const state = {
  me: null, email: "", pending: null, opener: null, busy: false, timer: 0,
  links: [], skipped: new Set(), poll: 0,
  request: null, requestId: null, requestTimer: 0, never: "", // an agent asking by email (P2s-3)
  keep: "", // a frozen account's keep link (DEC-010)
  reservation: null, reservationId: null, made: false, // a name reserved with an email (P2s-2)
  // Contacts and many agents (P2e-2)
  contacts: [], invites: [], fleets: [], shownContacts: new Set(),
  find: "", showAll: false, picking: false, picked: new Set(), openFleet: null,
  agent: null, agentView: null, many: null, invite: null, found: null, removing: null,
};

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
  const screens = {
    loading: $("loading"), signin: $("signin"), code: $("code"), account: $("account"),
    request: $("request"), never: $("never"), reserve: $("reserve"), accept: $("accept"),
    keep: $("keep"),
  };
  for (const [name, el] of Object.entries(screens)) el.hidden = name !== screen;
}

// ---- signing in

function showSignIn() {
  closeSheet(false);
  state.me = null;
  const invited = Boolean(state.invite);
  $("signin-kicker").hidden = !invited;
  $("signin-title").textContent = invited ? "Someone invited you to connect on YouAM" : "Sign in or create an account";
  $("signin-lede").textContent = invited
    ? "Sign in to see who it's from. New to YouAM? The same code makes your account."
    : "Your YouAM account approves who your agents may talk to.";
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
  try { r = await api("/api/owner/sign-up", { email }); } finally { done(); }
  if (r.status === 422) return problem(input, $("email-problem"), "That doesn't look like an email address.");
  if (r.status === 429) return problem(input, $("email-problem"), "Too many tries from here. Wait a while, then try again.");
  if (!r.ok) throw new Error(`sign-up: ${r.status}`);
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
  if (!$("accept").hidden) return $("accept-title").focus();
  ($("first").hidden ? $("agents-title") : $("first-title")).focus();
}

async function resend() {
  const r = await api("/api/owner/sign-up", { email: state.email });
  if (r.status === 429) return say($("code-status"), "Too many tries from here. Wait a while, then try again.");
  if (!r.ok) throw new Error(`sign-up: ${r.status}`);
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
  // A session opened from a request email only sees that request.
  if (me.data.request || state.requestId) return loadRequest(me.data.request ?? state.requestId);
  // One opened from a reservation email only sets up that name.
  if (me.data.reservation || state.reservationId) {
    return loadReservation(me.data.reservation ?? state.reservationId);
  }
  if (state.invite) return openInvite();
  $("who-email").textContent = me.data.email;
  $("who-email").title = me.data.email; // the header may shorten a long one
  const first = !me.data.owner_id;
  let keys = [];
  if (!first) keys = (await api("/api/owner/passkeys")).data.passkeys ?? [];
  $("first").hidden = !first;
  $("keys").hidden = first;
  $("agents").hidden = first;
  $("contacts").hidden = first;
  $("owner-section").hidden = first;
  $("owner-id").textContent = me.data.owner_id ?? "";
  $("key-list").replaceChildren(...keys.map(passkeyItem));
  // One passkey: losing it means a new account (DEC-010), so ask for a second.
  $("one-key").hidden = first || keys.length !== 1;
  if (!first) await Promise.all([loadAgents(), loadContacts()]);
  show("account");
}

// ---- agents (P2d-3)

function text(tag, className, value) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  el.textContent = value;
  return el;
}

function quiet(label, handler) {
  const b = text("button", "btn btn-quiet", label);
  b.type = "button";
  on(b, "click", $("agents-status"), handler);
  return b;
}

function foot(...parts) {
  const el = document.createElement("div");
  el.className = "foot";
  el.append(...parts);
  return el;
}

async function waitingItem(link) {
  const li = document.createElement("li");
  const words = await wordsFor(link.agentKey);
  const kind = link.via === "link"
    ? `An agent you already run · if you approve, it starts ${startsOn(link.effectiveAt)}`
    : "A new agent · linked as soon as you approve";
  const box = document.createElement("input");
  box.type = "checkbox";
  box.checked = !state.skipped.has(link.id);
  box.addEventListener("change", () => {
    if (box.checked) state.skipped.delete(link.id); else state.skipped.add(link.id);
    approveLabel();
  });
  const check = document.createElement("label");
  check.className = "check";
  check.append(box, text("span", "", "Include in this approval"));
  const actions = document.createElement("div");
  actions.className = "actions";
  actions.append(quiet("Cancel", () => cancelLink(link)));
  li.append(text("span", "name", link.agent), text("span", "words", words.join(" ")),
    text("span", "meta", kind), foot(check, actions));
  return li;
}

const SHOWN = 8; // past this many agents: a tally, a find field, and "Show N more"
const RANK = { closed: 0, contacts: 1, open: 2 };

/** policy.widens: would this setting let anyone in that's out now? */
const widens = (link, policy, same) => RANK[policy] > RANK[link.policy] || (same && !link.sameOwner);

function policyLine(link) {
  if (link.policy === "open") return "Anyone can message it";
  if (link.policy === "closed") return "No one can message it";
  return link.sameOwner ? "Your contacts and your own agents can message it" : "Only your contacts can message it";
}

const fleetNamed = (id) => state.fleets.find((f) => f.id === id);

async function agentItem(link, { flat = false } = {}) {
  const li = document.createElement("li");
  const words = await wordsFor(link.agentKey);
  const pickable = state.picking && link.effective;
  let name;
  if (pickable) {
    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = state.picked.has(link.id);
    box.addEventListener("change", () => {
      if (box.checked) state.picked.add(link.id); else state.picked.delete(link.id);
      pickCount();
    });
    name = document.createElement("label");
    name.className = "check";
    name.append(box, text("span", "name", link.agent));
  } else {
    name = text("span", "name", link.agent);
  }
  const fleet = flat && link.fleet ? fleetNamed(link.fleet) : null;
  let meta = link.effective ? policyLine(link) : `Starts ${startsOn(link.effectiveAt)}`;
  if (fleet) meta = `${fleet.name} fleet · ${meta}`;
  if (link.private) meta += " · Private";
  const actions = document.createElement("div");
  actions.className = "actions";
  if (!state.picking) {
    actions.append(link.effective
      ? quiet("Manage", () => openAgent(link))
      : quiet("Cancel", () => cancelLink(link)));
  }
  li.append(name, text("span", "words", words.join(" ")), foot(text("span", "meta", meta), actions));
  return li;
}

/** One line for a fleet's agents: their shared setting, or how they differ. */
function setLine(links) {
  const kinds = new Set(links.map(policyLine));
  if (!links.length) return "No agents yet. The agents that use its code join it.";
  if (kinds.size === 1) return [...kinds][0].replace(/ it$/, " them");
  const n = (f) => links.filter(f).length;
  return "Set differently: " + [
    [n((l) => l.policy === "contacts" && l.sameOwner), "contacts and own agents"],
    [n((l) => l.policy === "contacts" && !l.sameOwner), "only contacts"],
    [n((l) => l.policy === "open"), "anyone"],
    [n((l) => l.policy === "closed"), "no one"],
  ].filter(([c]) => c).map(([c, t]) => `${c} ${t}`).join(" · ");
}

const membersOf = (fleet) => state.links.filter((l) => l.state === "active" && fleet.links.includes(l.id));

async function fleetItem(fleet) {
  const li = document.createElement("li");
  const members = membersOf(fleet);
  const open = state.openFleet === fleet.id;
  const actions = document.createElement("div");
  actions.className = "actions";
  if (members.length) {
    const toggle = quiet(open ? "Hide agents" : "Show agents", async () => {
      state.openFleet = open ? null : fleet.id;
      const at = state.fleets.indexOf(fleet);
      await renderAgents();
      // The row was drawn again: focus stays on its toggle.
      $("fleet-list").children[at]?.querySelector(":scope > .foot button")?.focus();
    });
    toggle.setAttribute("aria-expanded", String(open));
    actions.append(toggle);
  }
  actions.append(quiet("Manage", () => openMany({ fleet })));
  const count = members.length === 1 ? "1 agent" : `${members.length} agents`;
  li.append(text("span", "name", fleet.name), text("span", "meta", `Fleet · ${count}`),
    foot(text("span", "meta", setLine(members)), actions));
  if (open) {
    const inner = document.createElement("ul");
    inner.className = "items";
    inner.setAttribute("aria-label", `Agents in the ${fleet.name} fleet`);
    inner.append(...await Promise.all(members.map((l) => agentItem(l))));
    li.append(inner);
  }
  return li;
}

function tally(live) {
  const n = (f) => live.filter(f).length;
  const el = $("agents-tally");
  const inFleets = live.filter((l) => l.fleet && fleetNamed(l.fleet)).length;
  const head = `${live.length} agents${state.fleets.length
    ? `, ${inFleets} of them in ${state.fleets.length === 1 ? "1 fleet" : `${state.fleets.length} fleets`}` : ""}. Who can message them: `;
  const parts = [
    [n((l) => l.policy === "contacts" && l.sameOwner), "your contacts and your own agents"],
    [n((l) => l.policy === "contacts" && !l.sameOwner), "only your contacts"],
    [n((l) => l.policy === "open"), "anyone"],
    [n((l) => l.policy === "closed"), "no one"],
  ].filter(([c]) => c);
  el.replaceChildren(head);
  parts.forEach(([c, t], i) => {
    if (i) el.append(" · ");
    el.append(text("b", "", String(c)), ` ${t}`);
  });
  el.append(".");
}

function pickCount() {
  const n = state.picked.size;
  $("pick-count").textContent = n === 1 ? "1 chosen" : `${n} chosen`;
  $("pick-set").disabled = n === 0;
  $("pick-fleet").disabled = n === 0;
}

/** The live agents, from what's loaded: fleets first, then the rest. */
async function renderAgents() {
  const live = state.links.filter((l) => l.state === "active");
  const effective = live.filter((l) => l.effective);
  const many = live.length > SHOWN;
  const flat = Boolean(state.find) || state.picking;
  const grouped = !flat && state.fleets.length > 0;
  $("agents-tally").hidden = !many;
  if (many) tally(live);
  $("find").hidden = effective.length < 2 && !state.fleets.length;
  $("find-field").hidden = !many;
  $("pick-start").hidden = state.picking || effective.length < 2;
  $("fleets").hidden = !grouped;
  if (grouped) $("fleet-list").replaceChildren(...await Promise.all(state.fleets.map(fleetItem)));
  const loose = grouped ? live.filter((l) => !l.fleet || !fleetNamed(l.fleet)) : live;
  const matching = state.find ? loose.filter((l) => l.agent.toLowerCase().includes(state.find)) : loose;
  const shown = state.showAll || flat ? matching : matching.slice(0, SHOWN);
  $("loose-title").hidden = !grouped || !loose.length;
  $("agent-list").replaceChildren(...await Promise.all(shown.map((l) => agentItem(l, { flat }))));
  $("agent-list").hidden = !shown.length;
  $("agents-none").hidden = !state.find || matching.length > 0;
  const more = matching.length - shown.length;
  $("agents-more").hidden = more <= 0;
  $("show-more").textContent = `Show ${more} more`;
  $("pick-bar").hidden = !state.picking;
  if (state.picking) pickCount();
}

function chosen() {
  return state.links.filter((l) => l.state === "waiting" && !state.skipped.has(l.id));
}

function approveLabel() {
  const n = chosen().length;
  const button = $("approve-waiting");
  button.disabled = n === 0;
  button.textContent = n === 1 ? "Approve 1 agent" : `Approve ${n} agents`;
}

function askingItem(request) {
  const li = document.createElement("li");
  const kind = request.via === "link"
    ? "Asked by email · an agent someone already runs: it starts 72 hours after it signs"
    : "Asked by email · a new agent: linked as soon as you approve";
  const actions = document.createElement("div");
  actions.className = "actions";
  actions.append(
    quiet("Accept", () => acceptAsking(request)),
    quiet("Decline", () => declineAsking(request)),
  );
  li.append(text("span", "name", request.agent), text("span", "words", request.words.join(" ")),
    foot(text("span", "meta", kind), actions));
  return li;
}

async function acceptAsking(request) {
  const r = await api(`/api/owner/requests/${request.id}/accept`, {});
  if (!r.ok) return afterChange(r.data.detail ?? AGAIN);
  await afterChange(`Accepted ${request.agent}. It signs its part next, then waits for you here.`);
}

async function declineAsking(request) {
  const r = await api(`/api/owner/requests/${request.id}/decline`, { block: false });
  if (!r.ok) return afterChange(r.data.detail ?? AGAIN);
  await afterChange(`Declined ${request.agent}.`);
}

function heldItem(held) {
  const li = document.createElement("li");
  const actions = document.createElement("div");
  actions.className = "actions";
  actions.append(quiet("Make a setup code", () => makeNamedCode(held, $("agents-status"))));
  li.append(text("span", "name", held.address),
    foot(text("span", "meta", `Held for you until ${startsOn(held.expiresAt)}`), actions));
  return li;
}

async function loadAgents() {
  const r = await api("/api/owner/links");
  if (!r.ok) throw new Error(`links: ${r.status}`);
  const kept = await api("/api/owner/reservations");
  const held = kept.ok ? kept.data.reservations ?? [] : [];
  $("held-list").replaceChildren(...held.map(heldItem));
  $("held").hidden = !held.length;
  const asked = await api("/api/owner/requests");
  const asking = asked.ok ? (asked.data.requests ?? []).filter((q) => q.state === "open") : [];
  $("asking-list").replaceChildren(...asking.map(askingItem));
  $("asking").hidden = !asking.length;
  const fleets = await api("/api/owner/fleets");
  state.fleets = fleets.ok ? fleets.data.fleets ?? [] : [];
  state.links = r.data.links ?? [];
  const waiting = state.links.filter((l) => l.state === "waiting");
  const live = state.links.filter((l) => l.state === "active");
  for (const id of [...state.skipped]) if (!waiting.some((l) => l.id === id)) state.skipped.delete(id);
  for (const id of [...state.picked]) if (!live.some((l) => l.id === id && l.effective)) state.picked.delete(id);
  if (state.openFleet && !fleetNamed(state.openFleet)) state.openFleet = null;
  $("waiting-list").replaceChildren(...await Promise.all(waiting.map(waitingItem)));
  $("waiting").hidden = !waiting.length;
  await renderAgents();
  $("agents-empty").hidden = Boolean(waiting.length || live.length || asking.length || held.length);
  mainButton();
  approveLabel();
}

// One main button on the page: approving agents or confirming someone when
// something waits, else adding an agent.
function mainButton() {
  const waiting = state.links.some((l) => l.state === "waiting");
  const confirming = state.invites.some((i) => i.state === "redeemed");
  $("add-agent").classList.toggle("btn-primary", !waiting && !confirming);
  $("add-agent").classList.toggle("btn-quiet", waiting || confirming);
}

async function refreshAgents() {
  if ($("account").hidden || !$("scrim").hidden || $("agents").hidden || state.busy) return;
  if (document.activeElement?.closest(".items")) return; // someone is in a list: leave it be
  try {
    await Promise.all([loadAgents(), loadContacts()]);
  } catch (err) { if (!(err instanceof Stop)) console.error(err); }
}

async function afterChange(message) {
  await loadAgents();
  say($("agents-status"), message);
  $("agents-title").focus();
}

async function cancelLink(link) {
  const r = await api(`/api/owner/links/${link.id}/cancel`, {});
  if (!r.ok) return afterChange(r.data.detail ?? AGAIN);
  await afterChange(`Cancelled the link to ${link.agent}.`);
}

async function makePrivate(link) {
  const r = await api(`/api/owner/links/${link.id}/private`, { private: true });
  if (!r.ok) return afterChange(r.data.detail ?? AGAIN);
  await afterChange(`${link.agent} is private: it isn't offered in introductions.`);
}

async function startApproval(kind, path, body, opener, extra) {
  const r = await api(path, body);
  if (!r.ok) return afterChange(r.data.detail ?? AGAIN);
  let screen;
  try {
    screen = await checkLinkApproval(kind, r.data, state.me.owner_id);
  } catch (err) {
    console.error(err);
    return afterChange(
      "This page stopped: what your passkey would sign didn't match what it would show. Nothing was signed.");
  }
  state.pending = { kind, answer: r.data, ...extra };
  openApprove(screen, opener);
}

function approveWaiting() {
  const ids = chosen().map((l) => l.id);
  if (!ids.length) return;
  return startApproval("links", "/api/owner/link-sets/approve/start", { ids }, $("approve-waiting"),
    { count: ids.length });
}

function startUnlink(link) {
  return startApproval("unlink", `/api/owner/links/${link.id}/unlink/start`, {}, $("agents-title"),
    { id: link.id, agent: link.agent });
}

// ---- approvals for contacts and settings (P2e-2)

const STOPPED = "This page stopped: what your passkey would sign didn't match what it would show. Nothing was signed.";

/**
 * Asks the relay for an approval, checks it here (checkContactApproval) and
 * opens the approval sheet. *how* = {finish, done(data), again()}. Returns the
 * refused answer, or null once the sheet is open (or the check stopped it).
 */
async function startContact(kind, path, body, ctx, opener, statusEl, how) {
  const r = await api(path, body);
  if (!r.ok) return r;
  let screen;
  try {
    screen = await checkContactApproval(kind, r.data, { ownerId: state.me.owner_id, ...ctx });
  } catch (err) {
    console.error(err);
    say(statusEl, STOPPED);
    return null;
  }
  state.pending = { kind: "contact", answer: r.data, ...how };
  openApprove(screen, opener);
  return null;
}

/** What the person picked in a who-can-message form ("agent" or "many"). */
function picked(prefix) {
  const policy = $(`${prefix}-open`).checked ? "open" : $(`${prefix}-contacts`).checked ? "contacts" : null;
  return { policy, same: policy === "open" ? true : $(`${prefix}-same`).checked };
}

function setChoice(prefix, policy, same, it) {
  $(`${prefix}-open`).checked = policy === "open";
  $(`${prefix}-contacts`).checked = policy === "contacts";
  $(`${prefix}-same`).checked = same;
  $(`${prefix}-legend`).textContent = `Who can message ${it}?`;
  $(`${prefix}-same-text`).textContent = `My other agents can message ${it} too`;
}

// ---- one agent: who can message it, keep carried-over contacts, unlink

async function openAgent(link) {
  const r = await api(`/api/owner/links/${link.id}/policy`);
  if (!r.ok) return afterChange(r.data.detail ?? AGAIN);
  state.agent = link;
  state.agentView = r.data;
  const v = r.data;
  $("agent-title").textContent = link.agent;
  const fleet = link.fleet ? fleetNamed(link.fleet) : null;
  $("agent-about").textContent = fleet ? `In the ${fleet.name} fleet` : "";
  $("agent-about").hidden = !fleet;
  setChoice("agent", v.policy, v.sameOwner, "it");
  const rows = v.carriedOver.filter((c) => !c.kept).map(carriedItem);
  $("carried-list").replaceChildren(...rows);
  $("agent-linked").textContent = `Linked ${addedOn(link.approvedAt ?? link.createdAt)}`;
  $("agent-private").hidden = link.private;
  say($("agent-problem"), "");
  agentForm();
  openSheet($("sheet-agent"), document.activeElement, $("agent-title"));
}

function carriedItem(c) {
  const li = document.createElement("li");
  const box = document.createElement("input");
  box.type = "checkbox";
  box.value = c.address;
  box.checked = !c.warn; // recent ones, and ones it never answered, start unticked
  box.addEventListener("change", agentForm);
  const label = document.createElement("label");
  label.className = "check";
  label.append(box, text("span", "name", c.address));
  const short = state.agent.agent.split("::")[0];
  const since = c.recent ? `Added ${addedOn(c.since)}` : `Allowed since ${addedOn(c.since)}`;
  const talk = c.twoWay ? "they've written to each other" : `${short} never replied`;
  li.append(label, text("span", "meta", `${since} · ${talk}`));
  return li;
}

const keeping = () => [...$("carried-list").querySelectorAll("input:checked")].map((b) => b.value);

function agentForm() {
  const { policy } = picked("agent");
  $("agent-same-row").hidden = policy !== "contacts";
  $("carried").hidden = policy !== "contacts" || !$("carried-list").children.length;
  const keep = $("carried").hidden ? 0 : keeping().length;
  $("agent-save").textContent = keep ? `Save and keep ${keep}` : "Save";
}

async function saveAgent() {
  const link = state.agent;
  const { policy, same } = picked("agent");
  if (!policy) return say($("agent-problem"), "Choose who can message it.");
  const v = state.agentView;
  const keep = policy === "contacts" ? keeping() : [];
  const changed = policy !== v.policy || same !== v.sameOwner;
  const done = async () => afterChange(`Saved who can message ${link.agent}.`);
  const keepThen = async () => {
    if (!keep.length) return done();
    const refused = await startContact("keep", `/api/owner/links/${link.id}/keep/start`, { contacts: keep },
      { agent: link.agent, addresses: keep }, $("agents-title"), $("agents-status"), {
        finish: `/api/owner/links/${link.id}/keep`, done, again: () => openAgent(link),
      });
    if (refused) return afterChange(refused.data.detail ?? AGAIN);
  };
  if (changed && widens(v, policy, same)) {
    const refused = await startContact("policies", `/api/owner/links/${link.id}/policy/approve/start`,
      { policy, sameOwner: same }, { agents: [{ agent: link.agent, agentKey: link.agentKey }], policy, sameOwner: same },
      $("agent-save"), $("agent-problem"), {
        finish: `/api/owner/links/${link.id}/policy/approve`, done: keepThen, again: () => openAgent(link),
      });
    if (refused) say($("agent-problem"), refused.data.detail ?? AGAIN);
    return;
  }
  if (changed) {
    const r = await api(`/api/owner/links/${link.id}/policy`, { policy, sameOwner: same });
    if (!r.ok) return say($("agent-problem"), r.data.detail ?? AGAIN);
  }
  closeSheet(false);
  return keepThen();
}

// ---- several agents, or a fleet: one setting for all of them

function openMany(target) {
  const fleet = target.fleet ?? null;
  const links = fleet ? membersOf(fleet).filter((l) => l.effective)
    : state.links.filter((l) => target.ids.includes(l.id));
  state.many = { fleet, links };
  const n = links.length;
  const short = links.map((l) => l.agent.split("::")[0]).join(", ");
  $("many-title").textContent = fleet ? fleet.name : `${n} agents`;
  $("many-names").textContent = fleet
    ? (n ? `Fleet · ${n === 1 ? "1 agent" : `${n} agents`}: ${short}` : "Fleet · no agents yet. The agents that use its code join it.")
    : short;
  const kinds = new Set(links.map((l) => `${l.policy}/${l.sameOwner}`));
  const [policy, same] = fleet?.policy ? [fleet.policy, fleet.sameOwner]
    : kinds.size === 1 ? [links[0].policy, links[0].sameOwner] : [null, true];
  setChoice("many", policy, same, "them");
  $("many-form").hidden = !n;
  $("many-fleet-foot").hidden = !fleet;
  $("many-save").textContent = n === 1 ? "Save for 1 agent" : `Save for ${n} agents`;
  say($("many-problem"), "");
  manyForm();
  openSheet($("sheet-many"), document.activeElement, $("many-title"));
}

function manyForm() {
  const { policy, same } = picked("many");
  const { fleet, links } = state.many;
  $("many-same-row").hidden = policy !== "contacts";
  const wider = policy && links.some((l) => widens(l, policy, same));
  const lines = [wider
    ? `Letting more in needs your passkey: one approval covers all ${links.length}.`
    : "Letting fewer in doesn't need your passkey."];
  if (fleet) lines.push("Agents that join this fleet later start with this setting.");
  $("many-hint").textContent = lines.join(" ");
}

async function saveMany() {
  const { fleet, links } = state.many;
  const { policy, same } = picked("many");
  if (!policy) return say($("many-problem"), "Choose who can message them.");
  const body = fleet ? { fleet: fleet.id } : { links: links.map((l) => l.id) };
  Object.assign(body, { policy, sameOwner: same });
  const n = links.length;
  const done = async () => {
    state.picking = false;
    state.picked.clear();
    await afterChange(`Saved who can message ${fleet ? `the ${fleet.name} fleet` : n === 1 ? "1 agent" : `${n} agents`}.`);
  };
  if (links.some((l) => widens(l, policy, same))) {
    const refused = await startContact("policies", "/api/owner/policy/approve/start", body, {
      agents: links.map((l) => ({ agent: l.agent, agentKey: l.agentKey })), policy, sameOwner: same,
      fleet: fleet?.name,
    }, $("many-save"), $("many-problem"), {
      finish: "/api/owner/policy/approve", done, again: () => openMany(fleet ? { fleet } : { ids: body.links }),
    });
    if (refused) say($("many-problem"), refused.data.detail ?? AGAIN);
    return;
  }
  const r = await api("/api/owner/policy", body);
  if (!r.ok) return say($("many-problem"), r.data.detail ?? AGAIN);
  closeSheet(false);
  await done();
}

// ---- fleets: grouping only, so no passkey

const FLEET_NAME = "Use 1 to 40 characters on one line, without quotation marks.";

function fleetNameProblem(name) {
  const tidy = name.split(/\s+/).filter(Boolean).join(" ");
  if (!tidy || tidy.length > 40 || name.includes('"') || /[\x00-\x1f\x7f]/.test(name)) return FLEET_NAME;
  return "";
}

function openInto() {
  const ids = [...state.picked];
  const choice = $("into-choice");
  for (const old of [...choice.querySelectorAll(".option")].slice(1)) old.remove();
  for (const fleet of state.fleets) {
    const input = document.createElement("input");
    input.type = "radio";
    input.name = "into";
    input.value = String(fleet.id);
    input.addEventListener("change", intoForm);
    const span = document.createElement("span");
    const n = membersOf(fleet).length;
    span.append(fleet.name, text("span", "hint", n === 1 ? "1 agent" : `${n} agents`));
    const label = document.createElement("label");
    label.className = "option";
    label.append(input, " ", span);
    choice.append(label);
  }
  $("into-new").checked = true;
  $("into-name").value = "";
  problem($("into-name"), $("into-problem"), "");
  $("into-title").textContent = ids.length === 1 ? "Put 1 agent in a fleet" : `Put ${ids.length} agents in a fleet`;
  intoForm();
  openSheet($("sheet-into"), $("pick-fleet"), $("into-title"));
}

function intoForm() {
  const fresh = $("into-new").checked;
  $("into-name-field").hidden = !fresh;
  const n = state.picked.size;
  $("into-go").textContent = fresh ? "Make the fleet" : n === 1 ? "Move 1 agent" : `Move ${n} agents`;
}

async function saveInto() {
  const ids = [...state.picked];
  const into = $("into-choice").querySelector("input:checked");
  let r;
  let message;
  if (into.value === "new") {
    const name = $("into-name").value;
    const bad = fleetNameProblem(name);
    if (bad) return problem($("into-name"), $("into-problem"), bad);
    r = await api("/api/owner/fleets", { name, links: ids });
    message = `Made the fleet ${r.data.name ?? name.trim()}.`;
  } else {
    const fleet = fleetNamed(Number(into.value));
    r = await api("/api/owner/fleets/move", { links: ids, fleet: fleet.id });
    message = `Moved ${ids.length === 1 ? "1 agent" : `${ids.length} agents`} to ${fleet.name}.`;
  }
  if (!r.ok) {
    return problem($("into-name"), $("into-problem"), r.status === 422 ? FLEET_NAME : r.data.detail ?? AGAIN);
  }
  closeSheet(false);
  state.picking = false;
  state.picked.clear();
  await afterChange(message);
}

function openRename() {
  const { fleet } = state.many;
  $("rename-input").value = fleet.name;
  problem($("rename-input"), $("rename-problem"), "");
  openSheet($("sheet-rename"), null, $("rename-input"));
}

async function saveRename() {
  const { fleet } = state.many;
  const name = $("rename-input").value;
  const bad = fleetNameProblem(name);
  if (bad) return problem($("rename-input"), $("rename-problem"), bad);
  const r = await api(`/api/owner/fleets/${fleet.id}/rename`, { name });
  if (!r.ok) {
    return problem($("rename-input"), $("rename-problem"), r.status === 422 ? FLEET_NAME : r.data.detail ?? AGAIN);
  }
  closeSheet(false);
  await afterChange(`Renamed the fleet ${r.data.name}.`);
}

async function ungroup() {
  const { fleet } = state.many;
  const r = await api(`/api/owner/fleets/${fleet.id}/ungroup`, {});
  if (!r.ok) return say($("many-problem"), r.data.detail ?? AGAIN);
  closeSheet(false);
  await afterChange(`Ungrouped ${fleet.name}. Its agents keep their settings.`);
}

function choosing(on) {
  state.picking = on;
  state.picked.clear();
  renderAgents().then(() => {
    const first = $("agent-list").querySelector("input");
    (on && first ? first : $("agents-title")).focus();
  }).catch((err) => console.error(err));
}

// ---- contacts

const MONTHS_LONG = ["January", "February", "March", "April", "May", "June", "July", "August",
  "September", "October", "November", "December"];

/** "March 2026" from the relay's UTC timestamp. */
function monthOf(iso) {
  const m = /^(\d{4})-(\d{2})-/.exec(iso ?? "");
  return m ? `${MONTHS_LONG[Number(m[2]) - 1]} ${m[1]}` : "";
}

async function loadContacts() {
  const [c, i] = await Promise.all([api("/api/owner/contacts"), api("/api/owner/invites")]);
  state.contacts = c.ok ? c.data.contacts ?? [] : [];
  state.invites = i.ok ? i.data.invites ?? [] : [];
  const confirming = state.invites.filter((x) => x.state === "redeemed");
  const open = state.invites.filter((x) => x.state === "open");
  $("confirm-list").replaceChildren(...confirming.map(confirmItem));
  $("confirming").hidden = !confirming.length;
  const asked = new Set(confirming.map((x) => x.invitee?.ownerId));
  // Someone waiting for you to confirm is shown once, under "Waiting for you".
  state.contacts = state.contacts.filter((c) => c.youAllow || !asked.has(c.ownerId));
  $("contact-list").replaceChildren(...state.contacts.map(contactItem));
  $("connected").hidden = !state.contacts.length;
  $("invite-list").replaceChildren(...open.map(inviteItem));
  $("invites").hidden = !open.length;
  $("contacts-empty").hidden = Boolean(confirming.length || state.contacts.length || open.length);
  mainButton();
}

async function afterContacts(message) {
  await loadContacts();
  say($("contacts-status"), message);
  $("contacts-title").focus();
}

function confirmItem(inv, i) {
  const li = document.createElement("li");
  const who = inv.invitee;
  const go = text("button", i === 0 ? "btn btn-primary" : "btn btn-quiet", "Confirm");
  go.type = "button";
  on(go, "click", $("contacts-status"), () => startConfirm(inv, go));
  const row = document.createElement("div");
  row.className = "row";
  row.append(go, quietIn($("contacts-status"), "Decline", () => cancelInvite(inv, `Declined ${who.email}.`)));
  li.append(text("span", "name", who.email), text("span", "words", inv.words.join(" ")),
    text("span", "meta", `Accepted your ${inv.how} · YouAM account since ${monthOf(who.since)}`), row);
  return li;
}

function quietIn(statusEl, label, handler) {
  const b = text("button", "btn btn-quiet", label);
  b.type = "button";
  on(b, "click", statusEl, handler);
  return b;
}

async function startConfirm(inv, opener) {
  const refused = await startContact("confirm", `/api/owner/invites/${inv.id}/confirm/start`, {},
    { invitee: inv.invitee }, opener, $("contacts-status"), {
      finish: `/api/owner/invites/${inv.id}/confirm`,
      done: () => afterContacts(`Connected with ${inv.invitee.email}.`),
      again: () => afterContacts(""),
    });
  if (refused) await afterContacts(refused.data.detail ?? AGAIN);
}

async function cancelInvite(inv, message) {
  const r = await api(`/api/owner/invites/${inv.id}/cancel`, {});
  await afterContacts(r.ok ? message : r.data.detail ?? AGAIN);
}

function contactItem(c) {
  const li = document.createElement("li");
  const agents = text("span", "meta", "");
  if (!c.agents.length) {
    agents.textContent = "No shared agents yet";
  } else if (c.agents.length > 3 && !state.shownContacts.has(c.ownerId)) {
    const all = text("button", "link", "Show them");
    all.type = "button";
    all.addEventListener("click", () => {
      state.shownContacts.add(c.ownerId);
      $("contact-list").replaceChildren(...state.contacts.map(contactItem));
      $("contacts-title").focus();
    });
    agents.append(`${c.agents.length} shared agents · `, all);
  } else {
    agents.textContent = `Their shared agents: ${c.agents.map((a) => a.address).join(", ")}`;
  }
  const meta = c.youAllow && c.theyAllow ? `Connected ${addedOn(c.connectedAt)} · until ${addedOn(c.until)}`
    : c.youAllow ? "You approved them · waiting for them to confirm"
      : "You removed them · yours can still message theirs";
  const actions = document.createElement("div");
  actions.className = "actions";
  if (c.youAllow) actions.append(quietIn($("contacts-status"), "Remove", () => openRemove(c)));
  li.append(text("span", "name", c.email), agents, foot(text("span", "meta", meta), actions));
  return li;
}

function inviteItem(inv) {
  const li = document.createElement("li");
  let name;
  let meta;
  let undo = "Cancel";
  if (inv.how === "code") {
    name = "Code";
    meta = `Works once, until ${startsOn(inv.redeemBy)}`;
  } else if (inv.how === "link") {
    name = "Link";
    meta = `Made ${addedOn(inv.createdAt)} · works once, until ${addedOn(inv.redeemBy)}`;
  } else {
    name = `Email to ${inv.email}`;
    meta = inv.sent ? `Sent · works once, until ${addedOn(inv.redeemBy)}` : `Sends at ${startsOn(inv.sendAt)}`;
    if (!inv.sent) undo = "Undo";
  }
  const message = undo === "Undo" ? `Undone: we won't email ${inv.email}.` : "Cancelled the invite.";
  const actions = document.createElement("div");
  actions.className = "actions";
  actions.append(quietIn($("contacts-status"), undo, () => cancelInvite(inv, message)));
  li.append(text("span", "name", name), text("span", "words", inv.words.join(" ")),
    foot(text("span", "meta", meta), actions));
  return li;
}

function openConnect() {
  $("how-code").checked = true;
  $("invite-email").value = "";
  say($("connect-problem"), "");
  connectForm();
  openSheet($("sheet-connect"), $("connect"), $("connect-title"));
}

const HOW = { code: "Make a code", link: "Make a link", email: "Continue" };

function connectForm() {
  const how = $("how-email").checked ? "email" : $("how-link").checked ? "link" : "code";
  $("invite-email-field").hidden = how !== "email";
  $("connect-go").textContent = HOW[how];
  return how;
}

async function connectGo() {
  const how = connectForm();
  if (how === "email") {
    const input = $("invite-email");
    const email = input.value.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return problem(input, $("connect-problem"), "Enter their email address.");
    }
    problem(input, $("connect-problem"), "");
    const refused = await startContact("invite", "/api/owner/invites/email/start", { email }, { email },
      $("connect"), $("contacts-status"), {
        finish: "/api/owner/invites/email",
        done: (data) => afterContacts(`We'll email ${email} at ${startsOn(data.sendAt)}. Until then you can undo it below.`),
        again: openConnect,
      });
    if (refused) problem(input, $("connect-problem"), refused.data.detail ?? AGAIN);
    return;
  }
  const done = busy($("connect-go"), how === "code" ? "Making a code…" : "Making a link…");
  let r;
  try { r = await api("/api/owner/invites", { how }); } finally { done(); }
  if (!r.ok) return say($("connect-problem"), r.data.detail ?? AGAIN);
  const inv = r.data;
  const code = how === "code";
  $("invite-made-kicker").textContent = code ? "Code" : "Link";
  $("invite-made-title").textContent = code ? "Read this to them" : "Send them this link";
  $("invite-code").textContent = inv.code ?? "";
  $("invite-code").hidden = !code;
  $("invite-link").textContent = inv.link ?? "";
  $("invite-link").hidden = code;
  $("invite-made-how").textContent = code
    ? `They sign in at ${location.host} and choose "Have a code from someone?". It works once, until ${startsOn(inv.redeemBy)}.`
    : `It works once, until ${addedOn(inv.redeemBy)}. This is the only time you'll see it: YouAM doesn't keep a copy.`;
  $("invite-words-hint").textContent = code
    ? "You'll both see these words. Check they match before you confirm."
    : "When they accept, you'll both see these words:";
  $("invite-words").textContent = inv.words.join(" ");
  say($("invite-copy-status"), "");
  $("invite-copy").hidden = code;
  $("invite-done").className = code ? "btn btn-primary" : "btn btn-quiet";
  openSheet($("sheet-invite-made"), null, $("invite-made-title"));
}

async function copyLink() {
  try {
    await navigator.clipboard.writeText($("invite-link").textContent);
    say($("invite-copy-status"), "Copied.");
  } catch {
    say($("invite-copy-status"), "Select the link and copy it.");
  }
}

async function inviteDone() {
  closeSheet(false);
  await afterContacts("");
}

function openRemove(c) {
  state.removing = c;
  $("remove-title").textContent = `Remove ${c.email}?`;
  $("remove-go").textContent = `Remove ${c.email}`;
  say($("remove-problem"), "");
  openSheet($("sheet-remove"), document.activeElement, $("remove-title"));
}

async function removeGo() {
  const c = state.removing;
  const r = await api(`/api/owner/contacts/${encodeURIComponent(c.ownerId)}/remove`, {});
  if (!r.ok) return say($("remove-problem"), r.data.detail ?? AGAIN);
  closeSheet(false);
  await afterContacts(`Removed ${c.email}. Their agents can't message yours now.`);
}

function openHaveCode() {
  $("their-code").value = "";
  problem($("their-code"), $("their-code-problem"), "");
  openSheet($("sheet-have-code"), $("have-code"), $("their-code"));
}

async function haveCodeGo() {
  const input = $("their-code");
  const code = input.value.trim();
  if (!code) return problem(input, $("their-code-problem"), "Type the code they read you.");
  const done = busy($("their-code-go"), "Finding it…");
  let r;
  try { r = await api("/api/owner/invites/find", { code }); } finally { done(); }
  if (!r.ok) {
    const why = r.status === 404 || r.status === 422 ? "That code didn't open an invite. Check it and try again."
      : r.data.detail ?? AGAIN;
    return problem(input, $("their-code-problem"), why);
  }
  closeSheet(false);
  state.invite = { code };
  showFound(r.data);
}

// ---- the accept page: /i/<id>#<secret>, or a code typed on the account page

function acceptParts({ lede = "", facts = false, check = false, means = "", why = "", go = false, form = false }) {
  $("accept-lede").textContent = lede;
  $("accept-lede").hidden = !lede;
  $("accept-facts").hidden = !facts;
  $("accept-check").hidden = !check;
  $("accept-means").textContent = means;
  $("accept-means").hidden = !means;
  say($("accept-problem"), why);
  $("accept-form").hidden = !form;
  $("accept-go").hidden = !go;
  $("accept-home").className = go || form ? "btn btn-quiet" : "btn btn-primary";
  $("accept-home").textContent = go ? "Not now" : "Go to your account";
}

function acceptEnded(title, why, lede = "Ask whoever sent it for a new one.") {
  $("accept-kicker").textContent = "Invitation";
  $("accept-title").textContent = title;
  acceptParts({ why, lede });
  show("accept");
  $("accept-title").focus();
}

const UNUSABLE = {
  no_invite: ["This invite can't be used", "That didn't open an invite. Check you opened the whole link."],
  used: ["This invite can't be used", "It was already used. If that wasn't you, whoever sent it has been told."],
  invite_ended: ["This invite can't be used", "It has ended."],
  own_invite: ["This is your own invite", "Send it to the person you want to connect with."],
  not_for_you: ["This invite is for someone else", "It was sent to another email address. Sign in with that one to accept it."],
};

function refusedInvite(r) {
  const [title, why] = UNUSABLE[r.data.error] ?? ["This invite can't be used right now", r.data.detail ?? AGAIN];
  acceptEnded(title, why, r.data.error === "own_invite" || r.data.error === "not_for_you" ? "" : undefined);
}

const inviteKey = () => (state.invite.code ? { code: state.invite.code }
  : { link: state.invite.link, secret: state.invite.secret });

async function openInvite() {
  if (state.invite.link && !state.invite.secret) {
    return acceptEnded("This invite can't be used", "The link is missing its end. Open the whole link again.");
  }
  if (!state.me.owner_id) {
    $("accept-kicker").textContent = "Invitation";
    $("accept-title").textContent = "Someone invited you to connect";
    acceptParts({ lede: "Add a passkey first. It's how you approve things, and it lets YouAM show you who this is from.",
      form: true });
    show("accept");
    return $("accept-name").focus();
  }
  const r = await api("/api/owner/invites/find", inviteKey());
  if (!r.ok) return refusedInvite(r);
  showFound(r.data);
}

function showFound(found) {
  state.found = found;
  const who = found.inviter;
  $("accept-kicker").textContent = "Invitation";
  $("accept-title").textContent = `${who.email} wants to connect`;
  $("accept-since").textContent = monthOf(who.since);
  $("accept-words").textContent = found.words.join(" ");
  acceptParts({
    facts: true, check: true, go: true,
    means: found.mode === "preapproved"
      ? "They've already approved you. If you connect, your shared agents and theirs can message each other for 90 days. You can remove them any time."
      : "If you connect, their shared agents can message yours for 90 days, and yours can message theirs once they confirm. You can remove them any time.",
  });
  show("accept");
  $("accept-title").focus();
}

async function acceptGo() {
  const found = state.found;
  const refused = await startContact("redeem", "/api/owner/invites/redeem/start", inviteKey(), {
    inviter: found.inviter, words: found.words, secret: state.invite.secret ?? null,
  }, $("accept-go"), $("accept-problem"), {
    finish: "/api/owner/invites/redeem", done: accepted, again: () => showFound(found),
  });
  if (refused) refusedInvite(refused);
}

function accepted(data) {
  const email = data.inviter.email;
  const connected = data.state === "connected";
  state.invite = null;
  state.found = null;
  $("accept-kicker").textContent = connected ? "Connected" : "Accepted";
  $("accept-title").textContent = connected ? `You're connected with ${email}` : `Waiting for ${email}`;
  acceptParts({ lede: connected
    ? "Your shared agents and theirs can message each other. You can remove them from your account any time."
    : "Their shared agents can message yours now. Yours can message theirs once they confirm on their YouAM page." });
  show("accept");
  $("accept-title").focus();
}

function acceptHome() {
  state.invite = null;
  state.found = null;
  if (location.pathname !== "/") history.replaceState(null, "", "/");
  return loadAccount().then(() => {
    if (!$("contacts").hidden) $("contacts-title").focus();
  });
}

// ---- codes for agents

function openCodeSheet() {
  $("code-count").value = "1";
  $("code-fleet").value = "";
  $("code-fleet-field").hidden = true;
  problem($("code-count"), $("code-count-problem"), "");
  problem($("code-fleet"), $("code-fleet-problem"), "");
  openSheet($("sheet-code"), $("add-agent"), $("code-sheet-title"));
}

const COMMANDS = {
  setup: ["On the new agent's computer, run this and type the code when it asks:", "uam init --setup"],
  setupMany: ["On each new agent's computer, run this and type the code when it asks:", "uam init --setup"],
  link: ["On the agent's computer, run this and type the code when it asks:", "uam owner link"],
  linkMany: ["Where the agents run, run this once and type the code. On each other computer, run uam owner link.",
    "uam owner link --all"],
};

async function makeCode() {
  const input = $("code-count");
  const count = Number(input.value);
  if (!Number.isInteger(count) || count < 1 || count > 25) {
    return problem(input, $("code-count-problem"), "Choose from 1 to 25 agents.");
  }
  problem(input, $("code-count-problem"), "");
  const fleet = count > 1 ? $("code-fleet").value.trim() : "";
  const bad = fleet ? fleetNameProblem(fleet) : "";
  if (bad) return problem($("code-fleet"), $("code-fleet-problem"), bad);
  problem($("code-fleet"), $("code-fleet-problem"), "");
  const kind = $("kind-link").checked ? "link" : "setup";
  const done = busy($("code-make"), "Making a code…");
  let r;
  try { r = await api("/api/owner/codes", { kind, count, ...(fleet ? { fleet } : {}) }); } finally { done(); }
  if (!r.ok) {
    if (r.status === 422 && fleet) return problem($("code-fleet"), $("code-fleet-problem"), FLEET_NAME);
    return problem(input, $("code-count-problem"), r.data.detail ?? AGAIN);
  }
  const [how, command] = COMMANDS[count > 1 ? `${kind}Many` : kind];
  $("made-code").textContent = r.data.code;
  $("made-how").textContent = how;
  $("made-command").textContent = command;
  $("made-when").textContent = count > 1
    ? `Works for ${count} agents until ${startsOn(r.data.expiresAt)}. Then approve them here together.`
      + (r.data.fleet ? ` They join the ${r.data.fleet.name} fleet.` : "")
    : `Works once, until ${startsOn(r.data.expiresAt)}. Then approve the agent here.`;
  openSheet($("sheet-code-made"), null, $("made-title"));
}

// A setup code for a reserved name: only an agent registering that name can use it.
async function makeNamedCode(held, statusEl) {
  const r = await api(`/api/owner/reservations/${held.id}/code`, {});
  if (!r.ok) return say(statusEl, r.data.detail ?? AGAIN);
  say(statusEl, "");
  $("made-code").textContent = r.data.code;
  $("made-how").textContent = `On the computer the agent runs on, run this and type the code when it asks. Only an agent named ${r.data.name} can use it.`;
  $("made-command").textContent = `uam init --setup --name ${r.data.name}`;
  $("made-when").textContent = `Works once, until ${startsOn(r.data.expiresAt)}. Then approve the agent from your account.`;
  openSheet($("sheet-code-made"), null, $("made-title"));
}

async function codeDone() {
  closeSheet(false);
  if (state.reservation) {
    state.made = true;
    renderReservation(state.reservation);
    return $("reserve-title").focus();
  }
  await afterChange("");
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
  if (pending?.kind) return; // a link approval made no passkey
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
    const path = p.finish ?? {
      keys: "/api/owner/keys/sign",
      links: "/api/owner/link-sets/approve",
      unlink: `/api/owner/links/${p.id}/unlink`,
    }[p.kind ?? "keys"];
    const r = await api(path, {
      credentialId: b64u(got.rawId),
      authenticatorData: b64u(got.response.authenticatorData),
      clientDataJSON: b64u(got.response.clientDataJSON),
      signature: b64u(got.response.signature),
    });
    if (r.ok) return p.finish ? finished(p, r.data) : p.kind ? approvedLinks(p) : added(p);
    stopped(r.data.error === "bad_challenge" ? "slow" : r.data.error === "log_moved" ? "moved" : "refused",
      r.data.detail);
  } finally {
    state.busy = false;
    done();
  }
}

async function finished(p, data) {
  state.pending = null;
  closeSheet(false);
  await p.done(data);
}

async function approvedLinks(p) {
  state.pending = null;
  closeSheet(false);
  if (state.request) {
    await loadRequest(state.request.id);
    return $("request-title").focus();
  }
  await afterChange(p.kind === "unlink" ? `Unlinked ${p.agent}.`
    : p.count === 1 ? "Approved 1 agent." : `Approved ${p.count} agents.`);
}

async function added(p) {
  state.pending = null;
  closeSheet(false);
  if (state.request) return acceptRequest(); // the first passkey was made to accept
  if (state.invite) { // the first passkey was made to accept an invitation
    const me = await api("/api/owner/me");
    if (me.ok) state.me = me.data;
    return openInvite();
  }
  if (state.reservation) { // the first passkey was made to get a setup code
    const me = await api("/api/owner/me");
    if (me.ok) state.me = me.data;
    renderReservation(state.reservation);
    return makeNamedCode(state.reservation, $("reserve-status"));
  }
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
  if (state.pending?.again) {
    const again = state.pending.again;
    state.pending = null;
    closeSheet(false);
    return again();
  }
  const linking = Boolean(state.pending?.kind);
  const first = state.pending?.first ?? !state.me?.owner_id;
  state.pending = null;
  closeSheet(false);
  if (state.request) {
    loadRequest(state.request.id).catch((err) => console.error(err));
  } else if (state.reservation) {
    $("reserve-title").focus();
  } else if (linking) {
    afterChange("").catch((err) => console.error(err));
  } else if (first) {
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
  for (const s of $("scrim").children) s.hidden = s !== sheet;
  $("scrim").hidden = false;
  $("account").inert = true;
  $("request").inert = true;
  $("reserve").inert = true;
  $("accept").inert = true;
  if (opener && !state.opener) state.opener = opener; // the first opener is where focus returns
  focus.focus();
}

function closeSheet(returnFocus) {
  clearTimeout(state.timer);
  $("scrim").hidden = true;
  $("account").inert = false;
  $("request").inert = false;
  $("reserve").inert = false;
  $("accept").inert = false;
  const opener = state.opener;
  state.opener = null;
  if (!returnFocus) return;
  if (opener && opener.offsetParent !== null) {
    opener.focus();
  } else if (!$("request").hidden) {
    $("request-title").focus();
  } else if (!$("reserve").hidden) {
    $("reserve-title").focus();
  } else if (!$("accept").hidden) {
    $("accept-title").focus();
  } else {
    ($("keys").hidden ? $("first-title") : $("agents-title")).focus();
  }
}

function openName(opener = $("add")) {
  const input = $("name-input");
  input.value = "";
  problem(input, $("name-problem"), "");
  openSheet($("sheet-name"), opener, input);
}

function escape(e) {
  if (e.key !== "Escape" || $("scrim").hidden || state.busy) return;
  e.preventDefault();
  if (!$("sheet-approve").hidden) return cancelApproval();
  if (!$("sheet-code-made").hidden) return codeDone();
  if (!$("sheet-invite-made").hidden) return inviteDone();
  state.pending = null;
  closeSheet(true);
}

// ---- an agent asking by email (P2s-3)

const ENDED = {
  approved: "Done",
  declined: "You declined",
  expired: "This request expired",
  cancelled: "This request was cancelled",
};

function requestLede(q, fresh) {
  const starts = q.via === "link"
    ? "It already runs somewhere, so the link starts 72 hours after it signs, and whoever runs it can cancel until then."
    : "It's a new agent, so it's linked as soon as you approve.";
  return {
    open: fresh
      ? `If you know this agent, make a passkey to accept it. There's no password: your device asks for Face ID, a fingerprint or your PIN. ${starts}`
      : `If you know this agent, accept it, then approve it with your passkey once it has signed. ${starts}`,
    waiting_for_agent: "Accepted. Waiting for the agent to sign its part: it does this by itself, within seconds if it's online, or when it's next online. You can leave this page open.",
    waiting_for_you: "The agent signed. Check its words, then approve it with your passkey.",
    approved: q.via === "link"
      ? `${q.agent} is linked to your YouAM account. The link is waiting its 72 hours.`
      : `${q.agent} is linked to your YouAM account.`,
    declined: `${q.agent} wasn't linked. You can close this page.`,
    expired: "Requests last 7 days. Ask the agent to send a new one.",
    cancelled: "The agent asked someone else, or stopped asking. Nothing was linked.",
  }[q.state];
}

async function loadRequest(id) {
  clearTimeout(state.requestTimer);
  const r = await api(`/api/owner/requests/${id}`);
  if (!r.ok) return requestGone(r.data.detail ?? AGAIN);
  renderRequest(r.data);
  show("request");
}

function renderRequest(q) {
  state.request = q;
  const fresh = !state.me.owner_id;
  const live = ["open", "waiting_for_agent", "waiting_for_you"].includes(q.state);
  $("request-title").textContent = ENDED[q.state]
    ?? (fresh ? "An agent wants you as its owner" : "An agent wants to join your YouAM account");
  $("request-lede").textContent = requestLede(q, fresh);
  const meta = q.via === "link" ? "An agent someone already runs" : "A new agent";
  const li = document.createElement("li");
  li.append(text("span", "name", q.agent), text("span", "words", q.words.join(" ")),
    text("span", "meta", meta));
  $("request-item").replaceChildren(li);
  $("request-check").hidden = !live;
  $("request-form").hidden = !(q.state === "open" && fresh);
  const go = { open: fresh ? null : "Accept", waiting_for_you: "Approve with passkey",
    approved: "Open your account" }[q.state];
  $("request-go").hidden = !go;
  $("request-go").textContent = go ?? "";
  $("request-no").hidden = !live;
  if (q.state === "waiting_for_agent") {
    state.requestTimer = setTimeout(() => {
      if ($("scrim").hidden) loadRequest(q.id).catch((err) => { if (!(err instanceof Stop)) console.error(err); });
    }, 3000);
  }
}

function requestGone(why) {
  state.request = null;
  $("request-title").textContent = "This link doesn't work";
  $("request-lede").textContent = why;
  $("request-item").replaceChildren();
  for (const id of ["request-check", "request-form", "request-go", "request-no"]) $(id).hidden = true;
  say($("request-status"), "");
  show("request");
  $("request-title").focus();
}

async function acceptRequest() {
  const q = state.request;
  const r = await api(`/api/owner/requests/${q.id}/accept`, {});
  const me = await api("/api/owner/me");
  if (me.ok) state.me = me.data;
  if (!r.ok) {
    await loadRequest(q.id);
    return say($("request-status"), r.data.detail ?? AGAIN);
  }
  say($("request-status"), "");
  renderRequest(r.data);
  $("request-title").focus();
}

async function requestGo() {
  const q = state.request;
  if (!q) return;
  if (q.state === "open") return acceptRequest();
  if (q.state === "waiting_for_you") {
    return startApproval("links", "/api/owner/link-sets/approve/start", { ids: [q.link] },
      $("request-go"), { count: 1 });
  }
  if (q.state === "approved") return openAccount();
}

async function openAccount() {
  // An email link's session only finishes its request or name: seeing the
  // account needs a normal sign-in.
  state.request = null;
  state.requestId = null;
  if (state.me?.request || state.me?.reservation) {
    const email = state.me.email;
    await api("/api/owner/sign-out", {});
    showSignIn();
    $("email").value = email;
    return $("signin-title").focus();
  }
  await loadAccount();
}

async function declineRequest(block) {
  const q = state.request;
  if (!q) return;
  const r = await api(`/api/owner/requests/${q.id}/decline`, { block });
  if (!r.ok) return say($("request-status"), r.data.detail ?? AGAIN);
  say($("request-status"), block ? "This agent can't email you again." : "");
  renderRequest(r.data);
  $("request-title").focus();
}

async function openFromEmail(token) {
  const r = await api("/api/owner/requests/open", { token });
  if (r.status === 410) return requestGone("This request has ended. Ask the agent to send a new one.");
  if (!r.ok) return requestGone("Check you opened the whole link from the email.");
  state.requestId = r.data.request.id;
  await loadAccount();
  $("request-title").focus();
}

// ---- a name reserved with an email (P2s-2)

async function loadReservation(id) {
  const r = await api("/api/owner/reservations");
  const held = r.ok ? (r.data.reservations ?? []).find((x) => x.id === id) : null;
  if (!held) return reservationGone("This name is no longer reserved. It may have expired, or an agent has it now.");
  renderReservation(held);
  show("reserve");
}

function renderReservation(held) {
  state.reservation = held;
  const fresh = !state.me.owner_id;
  $("reserve-title").textContent = state.made ? `Set up ${held.name}` : `${held.name} is reserved for you`;
  $("reserve-lede").textContent = state.made
    ? `Use the code on the computer ${held.name} runs on. Once it's set up, approve it from your YouAM account.`
    : fresh
      ? `Make a passkey to keep it, then you get a setup code for the agent. There's no password: your device asks for Face ID, a fingerprint or your PIN.`
      : "Make a setup code, then set up the agent with it.";
  const li = document.createElement("li");
  li.append(text("span", "name", held.address),
    text("span", "meta", `Held for you until ${startsOn(held.expiresAt)}`));
  $("reserve-item").replaceChildren(li);
  $("reserve-form").hidden = state.made || !fresh;
  const go = state.made ? "Open your account" : fresh ? null : "Make a setup code";
  $("reserve-go").hidden = !go;
  $("reserve-go").textContent = go ?? "";
}

function reservationGone(why) {
  state.reservation = null;
  $("reserve-title").textContent = "This link doesn't work";
  $("reserve-lede").textContent = why;
  $("reserve-item").replaceChildren();
  for (const id of ["reserve-form", "reserve-go"]) $(id).hidden = true;
  say($("reserve-status"), "");
  show("reserve");
  $("reserve-title").focus();
}

async function reserveGo() {
  const held = state.reservation;
  if (!held) return;
  if (state.made) {
    state.reservation = null;
    state.reservationId = null;
    return openAccount();
  }
  return makeNamedCode(held, $("reserve-status"));
}

async function openReservation(token) {
  const r = await api("/api/owner/reservations/open", { token });
  if (r.status === 410) return reservationGone("This name is no longer reserved. Reserve it again if it's still free.");
  if (!r.ok) return reservationGone("Check you opened the whole link from the email.");
  state.reservationId = r.data.reservation.id;
  await loadAccount();
  $("reserve-title").focus();
}

async function stopEmails() {
  const r = await api("/api/owner/requests/never", { token: state.never });
  if (!r.ok) return say($("never-problem"), r.status === 404
    ? "This link doesn't work. Check you opened the whole link from the email." : AGAIN);
  say($("never-problem"), "");
  $("never-title").textContent = "Done";
  $("never-lede").textContent = r.data.detail;
  $("never-go").hidden = true;
  $("never-title").focus();
}

async function keepAccount() {
  if (!state.keep) return location.assign("/"); // kept: the button signs in
  const r = await api("/api/owner/freeze/keep", { token: state.keep });
  if (!r.ok) return say($("keep-problem"), r.status === 404
    ? "This link has ended or was already used. If your account closed, you can make a new one with the same email." : AGAIN);
  say($("keep-problem"), "");
  $("keep-title").textContent = "Your account is back";
  $("keep-lede").textContent = r.data.detail;
  $("keep-go").textContent = "Sign in";
  state.keep = "";
  $("keep-title").focus();
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
  on($("one-key-add"), "click", $("keys-status"), () => openName($("one-key-add")));
  on($("keep-go"), "click", $("keep-problem"), keepAccount);
  on($("name-form"), "submit", $("name-problem"),
    () => createPasskey($("name-input"), $("name-problem"), $("name-create")));
  on($("name-cancel"), "click", $("name-problem"), () => closeSheet(true));
  on($("approve"), "click", $("approve-problem"), approve);
  on($("approve-cancel"), "click", $("approve-problem"), cancelApproval);
  on($("restart"), "click", $("stopped-text"), restart);
  on($("stopped-close"), "click", $("stopped-text"), () => { state.pending = null; closeSheet(true); });
  on($("add-agent"), "click", $("agents-status"), openCodeSheet);
  on($("code-sheet-form"), "submit", $("code-count-problem"), makeCode);
  on($("code-cancel"), "click", $("code-count-problem"), () => closeSheet(true));
  on($("made-done"), "click", $("agents-status"), codeDone);
  on($("approve-waiting"), "click", $("agents-status"), approveWaiting);
  on($("request-form"), "submit", $("request-problem"),
    () => createPasskey($("request-name"), $("request-problem"), $("request-create")));
  on($("request-go"), "click", $("request-status"), requestGo);
  on($("request-decline"), "click", $("request-status"), () => declineRequest(false));
  on($("request-block"), "click", $("request-status"), () => declineRequest(true));
  on($("never-go"), "click", $("never-problem"), stopEmails);
  on($("reserve-form"), "submit", $("reserve-problem"),
    () => createPasskey($("reserve-name"), $("reserve-problem"), $("reserve-create")));
  on($("reserve-go"), "click", $("reserve-status"), reserveGo);
  // Contacts, many agents and fleets (P2e-2)
  $("code-count").addEventListener("input", () => {
    $("code-fleet-field").hidden = !(Number($("code-count").value) > 1);
  });
  $("find-agent").addEventListener("input", () => {
    state.find = $("find-agent").value.trim().toLowerCase();
    renderAgents().catch((err) => console.error(err));
  });
  on($("show-more"), "click", $("agents-status"), async () => {
    state.showAll = true;
    await renderAgents();
    // Focus the first agent that was hidden.
    $("agent-list").children[SHOWN]?.querySelector("button, input")?.focus();
  });
  on($("pick-start"), "click", $("agents-status"), () => choosing(true));
  on($("pick-cancel"), "click", $("agents-status"), () => choosing(false));
  on($("pick-set"), "click", $("agents-status"), () => openMany({ ids: [...state.picked] }));
  on($("pick-fleet"), "click", $("agents-status"), openInto);
  for (const id of ["agent-open", "agent-contacts", "agent-same"]) $(id).addEventListener("change", agentForm);
  for (const id of ["many-open", "many-contacts", "many-same"]) $(id).addEventListener("change", manyForm);
  on($("agent-form"), "submit", $("agent-problem"), saveAgent);
  on($("agent-cancel"), "click", $("agent-problem"), () => closeSheet(true));
  on($("agent-private"), "click", $("agent-problem"), () => { closeSheet(false); return makePrivate(state.agent); });
  on($("agent-unlink"), "click", $("agent-problem"), () => { closeSheet(false); return startUnlink(state.agent); });
  on($("many-form"), "submit", $("many-problem"), saveMany);
  on($("many-cancel"), "click", $("many-problem"), () => closeSheet(true));
  on($("fleet-rename"), "click", $("many-problem"), openRename);
  on($("fleet-ungroup"), "click", $("many-problem"), ungroup);
  $("into-new").addEventListener("change", intoForm);
  on($("into-form"), "submit", $("into-problem"), saveInto);
  on($("into-cancel"), "click", $("into-problem"), () => closeSheet(true));
  on($("rename-form"), "submit", $("rename-problem"), saveRename);
  on($("rename-cancel"), "click", $("rename-problem"), () => closeSheet(true));
  on($("connect"), "click", $("contacts-status"), openConnect);
  for (const id of ["how-code", "how-link", "how-email"]) $(id).addEventListener("change", connectForm);
  on($("connect-form"), "submit", $("connect-problem"), connectGo);
  on($("connect-cancel"), "click", $("connect-problem"), () => closeSheet(true));
  on($("invite-copy"), "click", $("invite-copy-status"), copyLink);
  on($("invite-done"), "click", $("contacts-status"), inviteDone);
  on($("remove-go"), "click", $("remove-problem"), removeGo);
  on($("remove-cancel"), "click", $("remove-problem"), () => closeSheet(true));
  on($("have-code"), "click", $("contacts-status"), openHaveCode);
  on($("have-code-form"), "submit", $("their-code-problem"), haveCodeGo);
  on($("their-code-cancel"), "click", $("their-code-problem"), () => closeSheet(true));
  on($("accept-form"), "submit", $("accept-name-problem"),
    () => createPasskey($("accept-name"), $("accept-name-problem"), $("accept-create")));
  on($("accept-go"), "click", $("accept-problem"), acceptGo);
  on($("accept-home"), "click", $("accept-problem"), acceptHome);
  // Agents that redeem a code show up here without a reload.
  state.poll = setInterval(refreshAgents, 10_000);
  document.addEventListener("keydown", escape);
  // An invite link carries its secret in the fragment, which never reaches
  // the server; it leaves the address bar before anything else happens.
  const invite = /^\/i\/([A-Za-z0-9_-]{16})$/.exec(location.pathname);
  if (invite) {
    const secret = location.hash.slice(1);
    history.replaceState(null, "", location.pathname);
    state.invite = { link: invite[1], secret: /^[A-Za-z0-9_-]{22}$/.test(secret) ? secret : null };
  }
  // An email link carries its token in the fragment, which never reaches
  // the server; it leaves the address bar before anything else happens.
  const from = new URLSearchParams(invite ? "" : location.hash.slice(1));
  if (location.hash) history.replaceState(null, "", location.pathname);
  // A link pasted into this open tab only changes the fragment: start over.
  window.addEventListener("hashchange", () => location.reload());
  if (from.get("keep")) {
    state.keep = from.get("keep");
    show("keep");
    return $("keep-title").focus();
  }
  if (from.get("never")) {
    state.never = from.get("never");
    show("never");
    return $("never-title").focus();
  }
  const first = from.get("request") ? openFromEmail(from.get("request"))
    : from.get("reserve") ? openReservation(from.get("reserve")) : loadAccount();
  first.catch((err) => {
    if (err instanceof Stop) return;
    console.error(err);
    showSignIn();
  });
}


// The BIP39 English list (uam/data/bip39-english.txt), for the four words.
export const WORDS = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose improve impulse inch include income increase index indicate indoor industry infant inflict inform inhale inherit initial inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure meat mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral more morning mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay old olive olympic omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent park parrot party pass patch path patient patrol pattern pause pave payment peace peanut pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea search season seat second secret section security seed seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock soda soft solar soldier solid solution solve someone song soon sorry sort soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo".split(" ");

if (typeof document !== "undefined") start();
