# keyspill

Find API keys and tokens sitting in plain text on your machine.

**Read-only. No network. No daemon. No config. One file, no dependencies.**

```bash
python3 keyspill.py ~/Projects
```

It never sends anything anywhere. That is deliberate: a tool that hunts for your secrets
has no business phoning home, and the whole thing is one file you can read before you run
it.

## Why this exists

An audit of one working developer's laptop found **455 distinct keys in plain text across
1,241 files. 34 of them still authenticated** — including five live-mode payment keys
spread across two accounts the owner had forgotten were separate. Nothing was breached.
They had simply accumulated: in `.env` backups, in shell history, in old deployment notes,
and increasingly in AI chat transcripts.

That last one is new. Keys now leak into places that did not exist three years ago.

## What makes it different

**It is built around not crying wolf.** Matching `sk_live_` is easy. The reason secret
scanners get uninstalled is that they report your own build output as a security incident.

Run a `pip install` past most entropy-based scanners and they will flag wheel filenames,
compiler flags, `site-packages` paths and version strings. keyspill's test suite is mostly
false-positive tests, and every string in it was really captured as a "secret" by a naive
clipboard watcher during one `pip install`.

The signal that does the work: **real key material contains a long unbroken high-entropy
run.** The longest run in `typing_extensions-4.16.0` is ten characters. A secret's is
twenty or more, with digits scattered throughout rather than bunched at the end, and it is
not simply CamelCase words strung together.

**It also catches what class-counting scanners miss.** A 40-character lowercase hex token —
Cloudflare's shape, and a great many webhook secrets — has only two character classes, so
"must contain upper, lower, digits and punctuation" rejects it outright.

## Live config vs dead copies

Not every finding gets the same advice, and getting this backwards is dangerous.

- **Live config** (`.env`, `credentials`, `settings.json`) — something is reading this.
  **Rotate the key at the vendor.** Do not just delete it; that breaks the service.
- **Dead copies** (logs, `.bak` files, shell history, chat transcripts) — nothing runs off
  these, so they can be cleaned up. **Rotate anyway.** A key that has sat in a log or a
  chat transcript is already exposed, and deleting the file now does not un-expose it.

## Use it as a gate

Exit status is `1` when anything is found, so it works as a pre-commit hook or in CI:

```bash
python3 keyspill.py . --quiet || { echo "secret in the tree"; exit 1; }
```

```bash
python3 keyspill.py . --json        # machine-readable
python3 keyspill.py . --no-generic  # known vendor formats only, no entropy sweep
```

## What it detects

AWS, Anthropic, OpenAI, GitHub, GitLab, Google, Slack (tokens and webhooks), Stripe (live
and test), Shopify, Telegram, SendGrid, Twilio, npm, private key blocks, JWTs — plus a
conservative entropy sweep for formats it does not know by name.

## Limits, honestly

- Text files only. It will not read your database, your keychain, or an encrypted disk.
- It cannot tell you whether a key still works. That would mean sending your credentials
  to a vendor, and this tool does not make network calls.
- The entropy sweep is tuned to stay quiet. It will miss some short or low-entropy
  secrets. `--no-generic` makes it quieter still.
- Finding nothing is not proof you are clean.

## Tests

```bash
python3 test_keyspill.py
```

## Licence

MIT. Built by SavvyTech Consulting LLC.
