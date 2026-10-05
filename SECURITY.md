# Security model for the personal fork

Baseline: upstream v0.49.0, commit `7bd3a9bb98e26522a4cdff825c8b06a6e7f6f092`.
Fork release: 0.50.0. Review date: 2026-10-05.

## Boundaries enforced here

- Chrome supplies the tab, frame, document ID, origin, and URL. Page-provided identifiers are not trusted. The receiver checks both the complete origin (scheme, host, port) and exact URL immediately before filling.
- Native reads and delivery revalidate the selected document. Navigation during an authorization prompt fails closed. Popup actions target the top-level document; inline actions target their own frame. Credentials are never broadcast across frames.
- HTTPS is required except for the upstream local-development allowances: `localhost`, `127.0.0.1`, `[::1]`, `.localhost`, and `.test` over HTTP. These exceptions are for trusted development pages, not a guarantee of authenticated transport.
- OTP selections use opaque IDs in a per-document cache. A refreshed TOTP must match the selected account and domain; there is no fallback to another account's code.
- Only the extension popup may request an SRP challenge or submit its six-digit pairing code. The page's inline unlock action opens that popup. No pairing input is inserted into a website's DOM.
- Session changes clear the worker's password/OTP caches and invalidate pending reads. Delivery acknowledgements also recheck the session before caching a password or returning an OTP to the popup.
- Refresh clears caches and reloads lists. It never repeats a fill.

## Plaintext lifetime

The native protocol still returns plaintext into extension memory after decryption. Repeat-fill passwords and OTP lists expire after two minutes, with timer-based deletion and an additional expiration check on lookup. Closing a tab clears its worker caches. The content script's autofill and generated-password references also have two-minute timers; save deduplication clears after 15 seconds. Deferred new-password saves are bounded to ten entries and expire after two minutes. An OTP explicitly revealed in the popup is removed from that view after 30 seconds.

These are retention limits on extension-owned references, not cryptographic memory erasure. JavaScript garbage collection and browser scheduling are outside the extension's control. A filled value remains in the destination form until the page or user removes it. Locking the extension does not erase already filled forms or cancel a browser message already dispatched. A website can read credentials filled into its own fields.

## What remains trusted

This fork retains upstream's SRP/AES-GCM implementation, Apple's native helper and OS authorization, session keepalive, form heuristics, passkey hooks, and optional native utilities. These components were not formally verified. A compromised browser, malicious local process, compromised dependency/update, or malicious page at the selected origin remains a risk. Keeping the native session alive is an intentional usability tradeoff.

The extension retains upstream's broad website access and native-messaging permission; no new browser permissions were added. The optional auto-pair and policy helpers are not required for ordinary manual pairing and were not installed as part of this fork. Enabling them separately adds OS automation/policy behavior. Keep auto-pair off if manual pairing is the desired boundary.

The manifest retains Apple's public extension key to use its accepted extension ID. That public key is not a signature, endorsement, or security guarantee. This is for unpacked personal use, not Chrome Web Store distribution.

## Verification and limits

`node --test test-harness/security/*.test.*` runs the actual background/content code against dummy browser and native interfaces. Cases cover HTTP downgrade, port and URL changes, stale documents, navigation during reads, lock during reads and delivery, popup-only pairing, exact OTP account selection, and active cache expiration.

`node test-harness/automation/pin-session.test.mjs` exercises upstream protocol-session behavior with a mock native transport. It does not certify the cryptography or the real Apple helper.

`node test-harness/security/preview.mjs` serves the actual popup with dummy data only. Manual checks cover login search, empty-search Enter, arrow focus, settings, and pairing UI.

The legacy browser drivers in `test-harness/automation` replace message handlers with old mocks and expect inline pairing. They were not used as evidence for this fork. A successful real credential fill and Touch ID flow still require a user-run check in Brave; the audit and regression suite do not read the real vault.

## Maintenance

Review updates from the upstream remote before merging. Re-run the security tests and reload the unpacked extension and login pages after updating. Do not publish passwords, pairing codes, OTPs, session material, or vault contents in logs or bug reports.
