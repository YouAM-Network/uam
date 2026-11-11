# Owner page: design rules

The owner page is where a person signs in to their YouAM account,
manages passkeys and approves what their agents ask for. The relay serves it
on its own origin (for example `https://account.youam.network`), under a
strict content security policy. It's one HTML file, one stylesheet pair and
one script, with no framework and no inline code.

Files:

| File | What it holds |
|---|---|
| `src/uam/relay/owners/static/tokens.css` | Every raw value (base layer), and what each colour is for in each theme (meaning layer) |
| `src/uam/relay/owners/static/tokens.json` | The same tokens in the design-token (DTCG) format |
| `src/uam/relay/owners/static/owner.css` | The components, built from tokens only |
| `docs/design/owner-page/catalog.html` | Every component in every state, dark and light side by side |

`tests/relay/test_owner_page_assets.py` checks rules 7 to 10.

## Rules

### What people see

1. **One main button per state, solid ink** (light on dark, dark on light). Everything else is a quiet button or a link.
2. **The sentence being signed is shown exactly as it's signed**, in a quote block, before the device asks for a passkey. The page never paraphrases or shortens it.
3. **Every approval happens in the sheet.** The sheet shows only the sentence and "Approve with passkey". Keyboard focus stays inside it, and Escape or Cancel closes it without signing anything.
4. **Monochrome. The only hue is red, and red only for a problem**, such as a wrong code. Hierarchy comes from weight, size and space, not colour.
5. **Each fact appears once.** The email is in the header, not repeated on the page.
6. **Divide with hairline rules, not boxes or fills.** The only boxed things are fields, the quote and the sheet.

### How it's built

7. **Raw values live only in the base layer of `tokens.css`.** The meaning layer refers to base tokens, and never holds a value itself.
8. **`owner.css` uses tokens, never raw values.** That means no colours, px or rem. Breakpoints in `@media` lines are the one exception, because `var()` can't be used there. Colours come from meaning tokens only. Base colour tokens are never used directly.
9. **`tokens.json` is `tokens.css` in DTCG form.** A test keeps the two equal, so change both together.
10. **Dark is the brand default, and light follows the system.** Both themes define the same meanings. `[data-theme]` forces one, for the catalogue.
11. **Every control can be reached and used from the keyboard**, with a visible focus ring, and is at least 44 px tall (`--touch`). Text and controls meet WCAG AA contrast in both themes.
12. **Buttons say what happens:** "Email me a code", "Create passkey", "Approve with passkey". Never "OK" or "Submit". Use sentence case and plain words.
13. **The brand is the YouAM lockup, never typed.** The mark and the wordmark are one shape, traced from youam.network's logo (`/youam-logo.png`), drawn in the text colour. Never set "YouAM" in type next to the mark, change its proportions, or use the mark alone in the header.

## Components

| Component | Class | States |
|---|---|---|
| Brand: the YouAM lockup | `.brand`, `.logo` (one `#youam-logo` symbol per page) | one; 24 px tall, 28 px from 640 px wide |
| Field | `.field` | empty, filled, invalid (`aria-invalid="true"`) |
| Code field | `.field input.code` | empty, filled, invalid |
| Hint / problem | `.hint`, `.problem` | one each |
| Main button | `.btn.btn-primary` | rest, hover, focus, busy (`disabled`) |
| Quiet button | `.btn-quiet` | rest, hover, focus |
| Link | `.link` | rest, hover, focus |
| Quote | `.quote` | short, long (wraps anywhere) |
| Passkey list | `.passkeys` | empty, one, several |
| Owner id | `.owner-id` | one (breaks anywhere) |
| Header | `.head`, `.head-in`, `.who` | one |
| Callout | `.callout` | one |
| Agent list | `.items`, `.words`, `.meta`, `.foot`, `.actions` | waiting, asking by email, linked, starts later, private, empty |
| Include box | `.check` | ticked, not ticked |
| Choice of one | `.choice`, `.option` | one picked |
| Code and command | `.shown-code`, `.command` | one each |
| Sheet | `.scrim`, `.sheet`, `.kicker`, `.row` | approve, name a passkey, expired, add an agent, code made |

## States of the page

| # | State | What's open | The one main button |
|---|---|---|---|
| 1 | Signed out | Email field ("Sign in or create an account") | Email me a code |
| 2 | Code sent | Code field, "Send a new code" and "Use a different email" links | Sign in |
| 3 | Wrong code | Code field with a problem line | Sign in |
| 4 | Signed in, no passkey | Callout: name your first passkey | Create passkey |
| 5 | Approve first passkey | Sheet with the sentence | Approve with passkey |
| 6 | Account, nothing waiting | Agents (list or empty line), passkeys, owner id | Add an agent |
| 7 | Account, agents waiting | Waiting list with include boxes, then the rest | Approve N agents ("Add an agent" turns quiet) |
| 8 | Adding an agent | Sheet: which agent, how many | Make a code |
| 9 | Code made | Sheet: the code, the command to run, when it expires | Done |
| 10 | Approve agents | Sheet with the sentence (one agent or a set) | Approve with passkey |
| 11 | Approve unlinking | Sheet with the sentence | Approve with passkey |
| 12 | Adding a passkey | Sheet: name it | Create passkey |
| 13 | Approve new passkey | Sheet with the sentence | Approve with passkey |
| 14 | Request expired | Sheet: nothing changed | Start again |
| 15 | Agent request, someone new (from the email link) | The agent, its words, name a passkey; Decline · Decline and stop this agent asking | Create passkey and accept |
| 16 | Agent request, an account | The agent and its words; the decline links | Accept |
| 17 | Request accepted, the agent hasn't signed | The agent; the page checks every 3 seconds | none |
| 18 | Request signed by the agent | The agent and its words; the decline links | Approve with passkey |
| 19 | Request done, declined, expired or cancelled | What happened | Open your account (when done), else none |
| 20 | Stop emails about agents (from the email's link) | What it does | Stop these emails |
| 21 | Account, agents asking by email | "Asking by email" list with Accept and Decline on each, above the agents | Add an agent |
| 22 | Reserved name, someone new (from the email link) | The name and how long it's held; name a passkey | Create passkey and get a setup code |
| 23 | Reserved name, an account | The name and how long it's held | Make a setup code |
| 24 | Reserved name, code made | What to do with the code | Open your account |
| 25 | Reserved name link that ended | Why: expired, taken, or not the whole link | none |
| 26 | Account, names reserved for you | "Reserved for you" list with "Make a setup code" on each, above the agents | Add an agent |

"Add a passkey" is a quiet button once the account has a passkey: agents are what the page is for.
Agents that redeem a code appear without a reload (the page checks every 10 seconds while no sheet is open).

The email link carries its token in the fragment (`#request=…`, `#reserve=…`, `#never=…`): the server never sees it in a URL, and a mail scanner that fetches the page without running it does nothing. Opening the page shows the request (and makes the account, unfinished, if there is none); nothing is accepted, declined or stopped without a click. The script takes the fragment out of the address bar before anything else. A session opened from the link only finishes that request, or sets up that name: "Open your account" signs it out and asks for a normal sign-in.
