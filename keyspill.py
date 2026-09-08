#!/usr/bin/env python3
"""keyspill — find API keys and tokens sitting in plain text on your machine.

Read-only. No network. No daemon. No config. One file, no dependencies, and it never
sends anything anywhere — which is the whole point: a tool that hunts for your secrets
has no business phoning home, and you should be able to read all of it before you run it.

    python3 keyspill.py ~/Projects
    python3 keyspill.py . --json
    python3 keyspill.py . --quiet && echo "clean"

Exit status is 1 when something was found, so it works as a pre-commit hook or a CI gate.

MIT licensed. Built by SavvyTech Consulting LLC after an audit of one developer's laptop
turned up 455 keys in plain text across 1,241 files — 34 of which still authenticated,
including five live-mode payment keys across two accounts he had forgotten he had.
"""
from __future__ import annotations

import argparse, base64, json, math, os, re, sys
from pathlib import Path

__version__ = "0.1.0"

# ── what a key looks like ────────────────────────────────────────────────────
PATTERNS = [
    ("aws_access_key_id",    r"\bAKIA[0-9A-Z]{16}\b"),
    ("anthropic_api_key",    r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    ("openai_api_key",       r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
    ("github_token",         r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    ("gitlab_token",         r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    ("google_api_key",       r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("slack_token",          r"\bxox[baprse]-[A-Za-z0-9-]{10,}\b"),
    ("slack_webhook",        r"https://hooks\.slack\.com/services/[A-Za-z0-9/+]{40,}"),
    ("stripe_secret_key",    r"\b[sr]k_live_[A-Za-z0-9]{20,}\b"),
    ("stripe_test_key",      r"\b[sr]k_test_[A-Za-z0-9]{20,}\b"),
    ("shopify_admin_token",  r"\bshpat_[0-9a-fA-F]{32}\b"),
    ("telegram_bot_token",   r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}\b"),
    ("sendgrid_api_key",     r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"),
    ("twilio_account_sid",   r"\bAC[0-9a-fA-F]{32}\b"),
    ("npm_token",            r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("private_key_block",    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("jwt",                  r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
]
NAMED_RE = re.compile("|".join(f"(?P<{k}>{v})" for k, v in PATTERNS))
GENERIC_RE = re.compile(r"[A-Za-z0-9_\-.+/]{24,}")

# Long, mixed-case, digit-bearing strings that are never secrets. Without these the
# generic sweep reports a developer's own build output as a security incident, which is
# how scanners get uninstalled.
DEV_NOISE = re.compile(
    r"\.(whl|tar\.gz|egg|dist-info|so|dylib|min\.js|map|lock)$"
    r"|^-{1,2}[A-Za-z]"
    r"|site-packages|dist-packages|node_modules|/wheels/|\.cache/"
    r"|^(requirement|collecting|downloading|installing|building)\b", re.I)
VERSIONED = re.compile(r"^[A-Za-z][A-Za-z0-9_.]*(-[A-Za-z0-9_.]+)*-\d+(\.\d+)+", re.I)

# Content hashes are long, random and completely public. A single package-lock.json
# contributed 438 "secrets" before this went in — the exact crying-wolf failure that gets
# a scanner deleted. Two defences: the value's own prefix, and the word next to it.
DIGEST_PREFIX = re.compile(r"^(sha\d{1,3}|md5|blake\d?[bs]?\d*)-", re.I)
DIGEST_CONTEXT = re.compile(
    r"(integrity|checksum|digest|sha\d{1,3}|md5|etag|content[-_]hash|subresource"
    r"|\bhash\b|resolved|_id|revision|commit|blob|sourcemap)\W{0,4}$", re.I)

# Files whose whole purpose is recording content hashes. Named vendor patterns still run
# on them, because a real key pasted into a lockfile is still a real key.
LOCKFILES = re.compile(
    r"(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.ya?ml"
    r"|Cargo\.lock|composer\.lock|Gemfile\.lock|poetry\.lock|Pipfile\.lock|go\.sum"
    r"|packages\.lock\.json|flake\.lock|Podfile\.lock|Package\.resolved"
    r"|mix\.lock|pubspec\.lock|gradle\.lockfile|conan\.lock)$|\.min\.(js|css)$|\.map$", re.I)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_encoded_text(s):
    """Base64 that decodes to readable text is data, not a key.

    A 10,897-character blob was vaulted as a "secret"; it was a Python script the user had
    base64-encoded to paste safely. Real key material decodes to bytes, not to `import os`.
    """
    if len(s) < 40 or not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return False
    try:
        # A clipboard capture is often a partial one: the real blob was 10,897 characters,
        # which is not a multiple of four, so padding it produced invalid base64 and the
        # check silently failed. Decode the largest whole prefix instead.
        raw = base64.b64decode(s[: len(s) // 4 * 4], validate=False)
    except Exception:
        return False
    if not raw:
        return False
    # Judge the START, not the whole thing. A clipboard capture can run two blobs together
    # or stop mid-quantum, so the tail decodes to noise and drags the ratio down even when
    # the content is plainly source code. The first kilobyte settles it either way: a real
    # key decodes to noise immediately.
    head = raw[:1024]
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in head)
    return printable / len(head) > 0.9


def looks_random(s: str) -> bool:
    """Real key material is one long unbroken run of high-entropy characters.

    Package names, versions, paths and identifiers are short words joined by separators:
    the longest run in `typing_extensions-4.16.0` is ten characters. A secret's is twenty
    or more, carries digits throughout rather than only at the end, and is not simply
    CamelCase words strung together.
    """
    runs = re.findall(r"[A-Za-z0-9]+", s)
    if not runs:
        return False
    longest = max(runs, key=len)
    if len(longest) < 20 or entropy(longest) < 3.2:
        return False
    digits = sum(c.isdigit() for c in longest)
    if digits / len(longest) < 0.04:
        return False
    if not re.search(r"[0-9]", longest[: int(len(longest) * 0.75)]):
        return False
    words = re.findall(r"[A-Z][a-z]{2,}", longest)
    return sum(len(w) for w in words) / len(longest) < 0.55


def classify(v: str) -> str | None:
    m = NAMED_RE.fullmatch(v.strip()) or NAMED_RE.search(v)
    if m and m.lastgroup:
        return m.lastgroup
    s = v.strip()
    if len(s) < 24 or re.search(r"\s", s):
        return None
    classes = sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    has_digit = bool(re.search(r"[0-9]", s))
    is_list = len(re.findall(r"[/,|]", s)) >= 2 and not has_digit
    is_path = (s.startswith(("/", "~/", "./", "../")) or "://" in s or s.count("/") >= 2
               or re.search(r"\.(png|jpe?g|mp[34]|txt|md|json|html?|py|sh|log|csv|pdf|zip)$", s, re.I))
    is_host = bool(re.match(r"^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+$", s, re.I))
    solid = re.fullmatch(r"[A-Za-z0-9]{32,}", s) and entropy(s) >= 3.0
    if _is_encoded_text(s):
        return None       # encoded text, not key material
    if ((classes >= 3 and has_digit) or solid) and not (is_list or is_path or is_host):
        if not DEV_NOISE.search(s) and not VERSIONED.match(s) and looks_random(s):
            return "unrecognised_secret"
    return None


# ── where to look ────────────────────────────────────────────────────────────
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox",
             "site-packages", "dist-packages", ".mypy_cache", ".pytest_cache", ".next",
             "build", "dist", ".gradle", "target", "vendor", "Pods", ".terraform"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
            ".tar", ".mp4", ".mp3", ".aiff", ".wav", ".mov", ".woff", ".woff2", ".ttf",
            ".so", ".dylib", ".dll", ".exe", ".bin", ".pyc", ".whl", ".jar", ".class"}
MAX_BYTES = 8 * 1024 * 1024

# A key in a running config must be ROTATED, not deleted — redacting it breaks the service
# that reads it. A key in a log or a backup is a dead copy that can simply be cleaned up.
# Telling these apart is the difference between useful advice and dangerous advice.
LIVE_HINTS = re.compile(r"(^|/)\.?env($|\.|/)|(^|/)config|credentials|secrets|\.aws/|\.npmrc"
                        r"|settings\.(json|py|toml|ya?ml)$", re.I)
DEAD_HINTS = re.compile(r"\.(log|bak|old|save|orig|swp|tmp)$|~$|\.bak[-.]|history"
                        r"|\.jsonl$|/logs?/|transcript|_backup|\.zsh_history|\.bash_history", re.I)


def where(path: Path) -> str:
    p = str(path)
    if DEAD_HINTS.search(p):
        return "dead copy"
    if LIVE_HINTS.search(p):
        return "live config"
    return "source"


def mask(v: str, keep: int = 4) -> str:
    s = v.strip()
    return "…" * 3 if len(s) <= keep * 2 + 4 else f"{s[:keep]}…{s[-keep:]}"


def scan_text(text: str, generic: bool) -> list[tuple[int, str, str]]:
    out, seen = [], set()
    for m in NAMED_RE.finditer(text):
        out.append((text.count("\n", 0, m.start()) + 1, m.lastgroup, m.group(0)))
        seen.add((m.start(), m.end()))
    if generic:
        for m in GENERIC_RE.finditer(text):
            if any(m.start() < e and s < m.end() for s, e in seen):
                continue
            val = m.group(0)
            if DIGEST_PREFIX.match(val) or DIGEST_CONTEXT.search(text[max(0, m.start() - 24):m.start()]):
                continue
            k = classify(val)
            if k:
                out.append((text.count("\n", 0, m.start()) + 1, k, val))
    return out


def is_binary(p: Path) -> bool:
    """A NUL byte in the first 8 KB. Extension filtering is not enough on its own: the
    two false positives found in real-world testing were code-signature blobs inside
    `/usr/local/bin/python3`, which has no extension at all and reads as text otherwise.
    """
    try:
        with open(p, "rb") as f:
            return b"\0" in f.read(8192)
    except OSError:
        return True


def walk(root: Path):
    if root.is_file():
        if not is_binary(root):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".venv")]
        for f in filenames:
            p = Path(dirpath) / f
            if p.suffix.lower() in SKIP_EXT:
                continue
            try:
                if p.is_symlink() or p.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            if is_binary(p):
                continue
            yield p


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="keyspill", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default=".", help="file or folder to scan")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--quiet", action="store_true", help="exit status only")
    ap.add_argument("--no-generic", action="store_true",
                    help="only known vendor formats; no entropy sweep")
    ap.add_argument("--version", action="version", version=f"keyspill {__version__}")
    a = ap.parse_args()

    root = Path(a.path).expanduser().resolve()
    if not root.exists():
        print(f"No such path: {root}", file=sys.stderr)
        return 2

    keys: dict[str, dict] = {}
    files = 0
    for p in walk(root):
        try:
            text = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files += 1
        for line, kind, val in scan_text(text, not a.no_generic and not LOCKFILES.search(str(p))):
            e = keys.setdefault(val, {"kind": kind, "places": []})
            e["places"].append({"file": str(p), "line": line, "where": where(p)})

    if a.json:
        print(json.dumps({"scanned_files": files, "root": str(root), "findings": [
            {"kind": v["kind"], "preview": mask(k), "length": len(k),
             "occurrences": len(v["places"]), "places": v["places"][:50]}
            for k, v in sorted(keys.items(), key=lambda kv: -len(kv[1]["places"]))]}, indent=1))
        return 1 if keys else 0

    if a.quiet:
        return 1 if keys else 0

    if not keys:
        print(f"Clean. {files} files scanned, nothing key-shaped in plain text.")
        return 0

    live = sorted({pl["file"] for v in keys.values() for pl in v["places"] if pl["where"] == "live config"})
    dead = sorted({pl["file"] for v in keys.values() for pl in v["places"] if pl["where"] == "dead copy"})

    print(f"{len(keys)} distinct secret{'s' if len(keys) != 1 else ''} in plain text, "
          f"across {files} files scanned.\n")
    for val, v in sorted(keys.items(), key=lambda kv: -len(kv[1]["places"])):
        n = len(v["places"])
        print(f"  {v['kind']:<22} {mask(val):<14} len{len(val):<4} "
              f"{n} place{'s' if n != 1 else ''}")
        for pl in v["places"][:3]:
            print(f"      {pl['where']:<12} {pl['file']}:{pl['line']}")
        if n > 3:
            print(f"      … and {n - 3} more")

    print()
    if live:
        one = len(live) == 1
        print(f"{len(live)} file{'' if one else 's'} look{'s' if one else ''} like LIVE config. "
              f"Something is probably reading {'it' if one else 'these'}.")
        print("  Rotate the key at the vendor. Do NOT just delete it — that breaks the service.")
    if dead:
        one = len(dead) == 1
        print(f"\n{len(dead)} file{'' if one else 's'} {'is a dead copy' if one else 'are dead copies'} "
              "(logs, backups, shell history, transcripts).")
        print("  Nothing runs off these. They can be cleaned up — but rotate anyway:")
        print("  a key that has sat in a log or a chat transcript is already exposed.")
    print("\nkeyspill sent nothing anywhere. It only read files.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
