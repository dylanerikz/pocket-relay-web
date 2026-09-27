# Pocket Relay Web v0.1

A local-first iPhone web app for working on Briar Relay without a-Shell, Xcode, TestFlight, or a paid Apple developer account.

## Included now

- Installable PWA shell
- Offline service worker
- OPFS private on-device workspace
- Folder import from iOS Files
- SHA-256 session baseline
- Added / Modified / Deleted tracking
- Pocket Action v1 paste/import
- Pre-hash gates
- Exact replacement-count gates
- Rollback snapshots
- Automatic restore on failed action
- Post-hash gates
- JSON receipts
- Copy/download receipt ferry
- Work bundle export
- Workspace hash index export

## Fast $0 deployment

1. Create a GitHub repository named `pocket-relay-web`.
2. Upload the contents of this folder to the repository root.
3. In GitHub open **Settings → Pages**.
4. Choose **Deploy from a branch**.
5. Select `main` and `/ (root)`.
6. Open the published HTTPS address in Safari on the iPhone.
7. Tap **Share → Add to Home Screen**.
8. Launch Pocket Relay from the Home Screen.

## First test

1. Make a tiny folder with `demo.txt`.
2. Put `POCKET_RELAY_OLD` in it.
3. Import that folder into Pocket Relay.
4. Begin a session.
5. Import `SAMPLE_ACTION_PR-DEMO-0001.json`.
6. Press **GO**.
7. Confirm a GREEN receipt.
8. Refresh status and confirm `demo.txt` is modified.
9. Roll back.
10. Confirm the session is clean again.

Only after that should we import the large Relay source workspace.

## Ferry v0

ChatGPT → Pocket Action JSON → clipboard/file → Pocket Relay → receipt JSON → clipboard/file → ChatGPT.

The next milestone is Briar Courier, which removes the manual copy/paste while preserving the same action/receipt protocol.
