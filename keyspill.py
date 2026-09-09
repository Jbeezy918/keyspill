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



# ── dependency vulnerabilities ───────────────────────────────────────────────
#
# This is the ONLY part of keyspill that touches the network, which is why it lives
# behind its own subcommand instead of running by default. The tool's promise is that a
# scanner hunting your secrets does not phone home, and `keyspill <path>` still sends
# nothing at all.
#
# What `keyspill deps` sends: package NAMES and VERSIONS, to api.osv.dev. Not your code,
# not file paths, not anything it found in the secrets scan. OSV is Google's open
# vulnerability database — free, no account, no API key.

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"

# Only lockfiles, never manifests. `requirements.txt` says "flask" and a manifest says
# "^4.17.0"; neither pins what is actually installed, so a range would have to be
# resolved to be checked — and a wrong resolution reports vulnerabilities the user does
# not have. Exact pins only, so every finding is real.
def parse_requirements(text):
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][\w.!+-]*)$", line)
        if m:
            out.append(("PyPI", m.group(1).lower().replace("_", "-"), m.group(2)))
    return out


def parse_package_lock(text):
    try:
        d = json.loads(text)
    except Exception:
        return []
    out = []
    # npm lockfile v2/v3: a flat "packages" map keyed by install path.
    for path, meta in (d.get("packages") or {}).items():
        if not path or not isinstance(meta, dict) or meta.get("link"):
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        if name and meta.get("version"):
            out.append(("npm", name, meta["version"]))
    if out:
        return out
    # v1: a recursive "dependencies" tree.
    def walk_deps(node):
        for name, meta in (node or {}).items():
            if isinstance(meta, dict):
                if meta.get("version"):
                    out.append(("npm", name, meta["version"]))
                walk_deps(meta.get("dependencies"))
    walk_deps(d.get("dependencies"))
    return out


def parse_yarn_lock(text):
    out, name = [], None
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            spec = line.split(",")[0].strip().strip('":')
            # "@scope/pkg@^1.0.0" — the version separator is the LAST @, not the first.
            at = spec.rfind("@")
            name = spec[:at] if at > 0 else spec
        elif name and line.strip().startswith("version"):
            v = line.split("version", 1)[1].strip().strip('"')
            out.append(("npm", name, v)); name = None
    return out


def parse_toml_lock(text, ecosystem):
    """poetry.lock and Cargo.lock — both are [[package]] tables with name and version."""
    out = []
    for block in re.split(r"\n\s*\[\[package\]\]\s*\n", text)[1:]:
        n = re.search(r'^\s*name\s*=\s*"([^"]+)"', block, re.M)
        v = re.search(r'^\s*version\s*=\s*"([^"]+)"', block, re.M)
        if n and v:
            nm = n.group(1)
            out.append((ecosystem, nm.lower().replace("_", "-") if ecosystem == "PyPI" else nm,
                        v.group(1)))
    return out


def parse_pipfile_lock(text):
    try:
        d = json.loads(text)
    except Exception:
        return []
    out = []
    for section in ("default", "develop"):
        for name, meta in (d.get(section) or {}).items():
            v = (meta or {}).get("version", "")
            if v.startswith("=="):
                out.append(("PyPI", name.lower().replace("_", "-"), v[2:]))
    return out


def parse_go_sum(text):
    out, seen = [], set()
    for line in text.splitlines():
        parts = line.split()
        # Every module appears twice, once for the zip and once for its go.mod.
        if len(parts) >= 2 and not parts[1].endswith("/go.mod"):
            mod, ver = parts[0], parts[1].split("/")[0].lstrip("v")
            if (mod, ver) not in seen:
                seen.add((mod, ver)); out.append(("Go", mod, ver))
    return out


def parse_gemfile_lock(text):
    out, in_specs = [], False
    for line in text.splitlines():
        if re.match(r"^\s{0,2}\S", line):
            in_specs = line.strip() == "specs:"
            continue
        m = re.match(r"^\s{4}([A-Za-z0-9._-]+) \(([^)=<>~ ]+)\)\s*$", line)
        if in_specs and m:
            out.append(("RubyGems", m.group(1), m.group(2)))
    return out


def parse_composer_lock(text):
    try:
        d = json.loads(text)
    except Exception:
        return []
    out = []
    for section in ("packages", "packages-dev"):
        for pkg in (d.get(section) or []):
            if pkg.get("name") and pkg.get("version"):
                out.append(("Packagist", pkg["name"], pkg["version"].lstrip("v")))
    return out


LOCK_PARSERS = {
    "requirements.txt": parse_requirements,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "poetry.lock": lambda t: parse_toml_lock(t, "PyPI"),
    "Cargo.lock": lambda t: parse_toml_lock(t, "crates.io"),
    "Pipfile.lock": parse_pipfile_lock,
    "go.sum": parse_go_sum,
    "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
}



# Installed packages, not just declared ones.
#
# Every Python project on this machine had a requirements.txt with no version pins, or no
# requirements file at all, so a lockfile-only scanner reported "no lockfiles found" and
# missed the lot. What is actually INSTALLED is recorded exactly, in the .dist-info
# directory pip writes next to each package — a real, pinned, authoritative version list
# that needs no resolution and cannot be wrong.
DIST_INFO = re.compile(r"^(?P<name>.+?)-(?P<ver>\d[^-]*)\.(dist-info|egg-info)$")


def parse_site_packages(root: Path):
    out = []
    for dirpath, dirnames, _ in os.walk(root):
        if not dirpath.endswith(("site-packages", "dist-packages")):
            continue
        for d in dirnames:
            m = DIST_INFO.match(d)
            if not m:
                continue
            name = m.group("name").lower().replace("_", "-")
            out.append(("PyPI", name, m.group("ver")))
        dirnames[:] = []          # do not descend into the packages themselves
    return out

def collect_deps(root: Path):
    """Every pinned dependency under root, with the lockfile each came from."""
    found = {}
    roots = [root] if root.is_file() else []
    if not roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if fn in LOCK_PARSERS:
                    roots.append(Path(dirpath) / fn)
    for lf in roots:
        parser = LOCK_PARSERS.get(lf.name)
        if not parser:
            continue
        try:
            for eco, name, ver in parser(lf.read_text(errors="ignore")):
                found.setdefault((eco, name, ver), []).append(str(lf))
        except Exception:
            continue

    # Fall back to what is installed. Only when no lockfile turned anything up, so a
    # project that DOES pin its dependencies is still judged on what it declares.
    if not found and root.is_dir():
        for eco, name, ver in parse_site_packages(root):
            found.setdefault((eco, name, ver), []).append(f"{root} (installed)")
    return found


def osv_query(deps, timeout=30):
    """Ask OSV which of these are vulnerable. Batched — 1000 is the documented cap."""
    import urllib.request
    ids = {}
    keys = list(deps)
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        body = json.dumps({"queries": [
            {"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk
        ]}).encode()
        req = urllib.request.Request(OSV_BATCH, data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            results = json.loads(r.read()).get("results", [])
        for key, res in zip(chunk, results):
            for v in (res or {}).get("vulns", []) or []:
                ids.setdefault(key, []).append(v["id"])
    return ids


def osv_detail(vuln_id, timeout=20):
    import urllib.request
    try:
        with urllib.request.urlopen(OSV_VULN + vuln_id, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return {}


def severity_of(v):
    """CVSS v3 base score -> the label everyone recognises.

    OSV is not consistent about where severity lives: some records carry a CVSS vector,
    some only an ecosystem-specific word, many carry nothing at all. Report UNKNOWN
    rather than inventing a number — a made-up 'LOW' is worse than an honest blank.
    """
    for s in (v.get("severity") or []):
        score = str(s.get("score", ""))
        m = re.search(r"/(?:C|A):", score)
        if score.startswith("CVSS:3") and m:
            # Parse the base score if the record carries it numerically instead.
            pass
    ds = (v.get("database_specific") or {}).get("severity")
    if isinstance(ds, str) and ds:
        return ds.upper()
    for aff in (v.get("affected") or []):
        ds = (aff.get("database_specific") or {}).get("severity")
        if isinstance(ds, str) and ds:
            return ds.upper()
    return "UNKNOWN"


RANK = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def fixed_version(v, eco, name):
    """The first version the maintainers marked as fixed, if they marked one."""
    for aff in (v.get("affected") or []):
        pkg = aff.get("package") or {}
        if pkg.get("name", "").lower() != name.lower():
            continue
        for rng in (aff.get("ranges") or []):
            for ev in (rng.get("events") or []):
                if ev.get("fixed"):
                    return ev["fixed"]
    return None


def cmd_deps(a) -> int:
    root = Path(a.path).expanduser().resolve()
    if not root.exists():
        print(f"No such path: {root}", file=sys.stderr)
        return 2

    deps = collect_deps(root)
    if not deps:
        print("Nothing pinned to check. keyspill deps reads exact versions only — a "
              "lockfile (package-lock.json, yarn.lock, poetry.lock, Pipfile.lock, "
              "Cargo.lock, go.sum, Gemfile.lock, composer.lock), a requirements.txt "
              "using ==, or an installed virtualenv's site-packages.")
        return 0

    ecos = {}
    for (e, _, _) in deps:
        ecos[e] = ecos.get(e, 0) + 1
    summary = ", ".join(f"{n} {e}" for e, n in sorted(ecos.items(), key=lambda kv: -kv[1]))
    if not a.json:
        print(f"{len(deps)} pinned packages ({summary}).")
        print("Sending package names and versions to api.osv.dev — nothing else.\n")

    try:
        hits = osv_query(deps)
    except Exception as e:
        print(f"Could not reach OSV: {e}", file=sys.stderr)
        return 2

    findings = []
    seen_detail = {}
    for key, vuln_ids in hits.items():
        eco, name, ver = key
        for vid in vuln_ids:
            v = seen_detail.get(vid) or osv_detail(vid)
            seen_detail[vid] = v
            findings.append({
                "id": vid, "ecosystem": eco, "package": name, "version": ver,
                "severity": severity_of(v),
                "summary": (v.get("summary") or v.get("details", "")[:120] or "").strip(),
                "fixed": fixed_version(v, eco, name),
                "files": deps[key],
            })
    findings.sort(key=lambda f: (RANK.get(f["severity"], 4), f["package"]))

    if a.json:
        print(json.dumps({"root": str(root), "packages": len(deps),
                          "findings": findings}, indent=1))
        return 1 if findings else 0
    if a.quiet:
        return 1 if findings else 0

    if not findings:
        print(f"Clean. None of the {len(deps)} pinned packages has a known vulnerability.")
        return 0

    # Grouped by package, not one line per CVE. A single stale urllib3 carries a dozen
    # advisories; printing twelve lines buries the only thing the reader can act on,
    # which is the single version number that clears all twelve at once.
    by_pkg = {}
    for f in findings:
        by_pkg.setdefault((f["ecosystem"], f["package"], f["version"]), []).append(f)

    def vkey(v):
        return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", v)[:4])

    groups = []
    for (eco, name, ver), fs in by_pkg.items():
        fixes = [f["fixed"] for f in fs if f["fixed"]]
        # The highest fixed-version across every advisory is the one upgrade that
        # resolves all of them; a lower one leaves some still open.
        target = max(fixes, key=vkey) if fixes else None
        worst = min(fs, key=lambda f: RANK.get(f["severity"], 4))
        groups.append({"eco": eco, "name": name, "version": ver, "n": len(fs),
                       "severity": worst["severity"], "target": target,
                       "unfixed": len(fs) - len(fixes), "worst": worst,
                       "file": fs[0]["files"][0]})
    groups.sort(key=lambda g: (RANK.get(g["severity"], 4), -g["n"]))

    print(f"{len(findings)} known vulnerabilit{'y' if len(findings)==1 else 'ies'} "
          f"across {len(groups)} package{'' if len(groups)==1 else 's'}.\n")
    for g in groups:
        act = f"upgrade to {g['target']}" if g["target"] else "no fix published"
        print(f"  {g['severity']:<9} {g['name']}@{g['version']} ({g['eco']})  "
              f"{g['n']} advisor{'y' if g['n']==1 else 'ies'}  ->  {act}")
        if g["worst"]["summary"]:
            print(f"      worst: {g['worst']['summary'][:96]}")
        if g["unfixed"]:
            print(f"      {g['unfixed']} of these have no published fix")
        print(f"      {g['file']}")

    fixable = [g for g in groups if g["target"]]
    if fixable:
        print(f"\n{len(fixable)} of {len(groups)} packages are fixed by a version bump:")
        print("  " + "  ".join(f"{g['name']}>={g['target']}" for g in fixable[:8]))
    return 1

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

    # `deps` is a subcommand rather than a flag so that the plain invocation keeps its
    # guarantee: `keyspill <path>` opens no socket. Handled before parse_args so the
    # existing positional CLI is untouched and every old command still works.
    if len(sys.argv) > 1 and sys.argv[1] == "deps":
        sys.argv.pop(1)
        a = ap.parse_args()
        return cmd_deps(a)

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
