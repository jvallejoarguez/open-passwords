# Security model for the personal fork

Baseline: upstream v0.49.0, commit `7bd3a9bb98e26522a4cdff825c8b06a6e7f6f092`.
Fork release: 0.50.1. Review date: 2026-10-05.

## Boundaries enforced here

- Chrome supplies the tab, frame, document ID, origin, and URL. Page-provided identifiers are not trusted. The receiver checks both the complete origin (scheme, host, port) and exact URL immediately before filling.
- Native reads and delivery revalidate the selected document. Navigation during an authorization prompt fails closed. Popup actions target the top-level document; inline actions target their own frame. Credentials are never broadcast across frames.
- HTTPS is required except for the upstream local-development allowances: `localhost`, `127.0.0.1`, `[::1]`, `.localhost`, and `.test` over HTTP. These exceptions are for trusted development pages, not a guarantee of authenticated transport.
- OTP selections use opaque IDs in a per-document cache. A refreshed TOTP must match the selected account and domain; there is no fallback to another account's code.
- Only the extension popup may request an SRP challenge or submit its six-digit pairing code. The page's inline unlock action opens that popup. No pairing input is inserted into a website's DOM.
- Session changes clear the worker's password/OTP caches and invalidate pending reads. Delivery acknowledgements also recheck the session before caching a password or returning an OTP to the popup.
- Refresh clears caches and reloads lists. It never repeats a fill. Every handler it uses refuses HTTP (non-local) pages and stale documents before any native read.
- Inline suggestion rows are chosen only by trusted pointer or keyboard events. Enter activates the selected row only while it is in the open box and visible.

## Native session lifecycle

- Native replies carry no request ID, so requests are serialized and matched by command. A secret-bearing request that times out leaves a stale marker: its late reply is discarded, and the same command is refused until that reply arrives. If it has not arrived 30 seconds after the timeout, the next attempt drops the connection and requires pairing again. The marker never expires into reuse. A slow reply that does arrive does not cost the pairing.
- Pairing-handshake and capability timeouts drop the connection instead of waiting for an ambiguous late reply.
- The save request's acknowledgement is content-free and never read, so a missing ack counts as sent. A late ack may complete a later save early; it cannot carry data to it.
- Lock, native disconnect, `RELOGIN_NEEDED`, and `PASSWORDS_DISABLED` all use one reset path. That path closes the port, discards the SRP session, rejects every pending request (including Touch ID reads that have no timeout), and starts a fresh request queue. Pairing again opens a new connection when the user asks for a code.
- Queued work is bound to the connection, session, and challenge it was queued under. That binding is checked after every asynchronous step (encryption, decryption, SRP math, native reply), so older work cannot send on, unlock, or clear keys for a replacement session. Events from a replaced port are ignored.

## Plaintext lifetime

The native protocol still returns plaintext into extension memory after decryption. Repeat-fill passwords and OTP lists expire after two minutes, with timer-based deletion and an additional expiration check on lookup. Closing a tab clears its worker caches. The content script's autofill and generated-password references also have two-minute timers; save deduplication clears after 15 seconds. Deferred new-password saves are bounded to ten entries and expire after two minutes. Their timers are cleared when they are sent or dropped. An explicit Lock drops all of them. When an unlock flushes them, expiry and session are checked again after the account lookup and immediately before the native save (after any wait in the native queue), so a save cancelled or expired in the meantime is never sent. Other session losses (helper disconnect or re-login) keep them only until their normal expiry.

A successfully filled OTP is not returned to the popup. The code is returned to the popup only when it was not filled, so the popup can show it. An OTP explicitly revealed in the popup is removed from that view after 30 seconds. Inline OTP fills never return the code to the page.

These are retention limits on extension-owned references, not cryptographic memory erasure. JavaScript garbage collection and browser scheduling are outside the extension's control. A filled value remains in the destination form until the page or user removes it. Locking the extension does not erase already filled forms or cancel a browser message already dispatched. A website can read credentials filled into its own fields.

## What remains trusted

This fork retains upstream's SRP/AES-GCM implementation, Apple's native helper and OS authorization, session keepalive, form heuristics, passkey hooks, and optional native utilities. These components were not formally verified. A compromised browser, malicious local process, compromised dependency/update, or malicious page at the selected origin remains a risk. Keeping the native session alive is an intentional usability tradeoff.

The extension retains upstream's broad website access and native-messaging permission; no new browser permissions were added. The optional auto-pair and policy helpers are not required for ordinary manual pairing and were not installed as part of this fork. Enabling them separately adds OS automation/policy behavior. Keep auto-pair off if manual pairing is the desired boundary.

The manifest retains Apple's public extension key to use its accepted extension ID. That public key is not a signature, endorsement, or security guarantee. This is for unpacked personal use, not Chrome Web Store distribution.

## Verification and limits

`node --test test-harness/security/*.test.*` runs the actual background/content code against dummy browser and native interfaces. Cases cover HTTP downgrade (including every refresh handler), port and URL changes, stale documents, navigation during reads, lock during reads and delivery, popup-only pairing, exact OTP account selection, OTP plaintext responses, deferred-save expiry and Lock cancellation, synthetic versus trusted row selection, and active cache expiration.

`protocol.test.mjs` runs the actual `src/protocol.js` against `fake-native.mjs`, a fake native port that performs a real SRP and AES-GCM exchange with dummy PINs. It covers late replies after timeouts, unanswered replies, Lock and native disconnect during no-timeout reads, stale port events, re-login recovery, work queued or encrypting across a reset, and verification races. It also covers handshake timeouts and save acknowledgements. The fake port was written from the extension's side of the protocol. It shows that the client behaves consistently with itself, not that it matches Apple's helper.

`node test-harness/automation/pin-session.test.mjs` exercises upstream protocol-session behavior with a mock native transport. It does not certify the cryptography or the real Apple helper.

`node test-harness/security/preview.mjs` serves the actual popup with dummy data only. Manual checks cover login search, empty-search Enter, arrow focus, settings, and pairing UI.

Known limits of the lifecycle fixes: an unanswered secret-bearing reply makes that one command unavailable for up to 30 seconds and then forces re-pairing. Correct matching still assumes the helper sends at most one reply per request. The inline selector remains part of the page DOM: a page can restyle or move it under the user's real pointer. Trusted-event and visibility checks do not make it browser-owned UI. A save already handed to the helper cannot be recalled by Lock.

The legacy browser drivers in `test-harness/automation` replace message handlers with old mocks and expect inline pairing. They were not used as evidence for this fork. A successful real credential fill and Touch ID flow still require a user-run check in Brave; the audit and regression suite do not read the real vault.

## Maintenance

Review updates from the upstream remote before merging. Re-run the security tests and reload the unpacked extension and login pages after updating. Do not publish passwords, pairing codes, OTPs, session material, or vault contents in logs or bug reports.
