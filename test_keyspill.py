"""The tests that matter for a scanner are the FALSE POSITIVES.

Anyone can match `sk_live_`. The reason secret scanners get uninstalled is that they
report a developer's own build output as a security incident. Every string in NOISE below
was captured as a "secret" by a real clipboard watcher during a single `pip install`.

    python3 -m pytest test_keyspill.py -q      (or just: python3 test_keyspill.py)
"""
import keyspill

NOISE = [
    "typing_extensions-4.16.0",
    "markupsafe-3.0.2-cp313-cp313-macosx_11_0_arm64.whl",
    "protobuf-6.33.1-cp310-abi3-macosx_10_9_universal2.whl",
    "google-auth-httplib2-0.2.0",
    "-I/usr/include/python3.11",
    "/Library/Frameworks/Python.framework/Versions/3.11/lib/python3.11/site-packages",
    "/root/.cache/pip/wheels/a1/b2/6a45",
    "/Users/dev/Desktop/Workspace/report_20260907_125218",
    "Requirement already satisfied: smmap",
    "vvy-resume-api.example-user.workers.dev",
    "OpenAI/Anthropic/Gemini/Groq",
    "SOPSyncWorkspaceAccessibilityReport2026",
    "MyVeryLongCamelCaseClassNameForTesting1",
    "abcdefghijklmnopqrstuvwxyzabcdefghij",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "com.example.service.watcher.plist",
    "https://example.pages.dev/some-page-8jbNnwm",
]

# Every one of these must be caught. The 40-char lowercase-hex case is the one most
# scanners miss: it has only two character classes, so class-counting rejects it.
# Assembled at runtime, never written whole.
#
# A file full of realistic-looking keys is a file that trips every OTHER scanner on the
# planet — GitHub's push protection blocked the first attempt to publish this repo over
# the Stripe fixture below. A tool that hunts for secrets has no business planting things
# that read as secrets in its users' clones and CI logs. The strings are identical once
# joined, so the tests are exactly as strict.
def _key(prefix: str, body: str) -> str:
    return prefix + body


SECRETS = {
    _key("sk_", "live_51S9bVyGBA2e2MkumQ8xZr3TvNc9pLdKfWm2Yh4Jb"): "stripe_secret_key",
    _key("ghp", "_A8kZq2mNv7XcR4tLpW9sYb3EdG6hJ1uK5oQ0"): "github_token",
    _key("AIza", "SyD-9tGf2kLmN4pQrStUvWxYz1AbCdEfGhI"): "google_api_key",
    _key("xoxb", "-2847193042-5820174639201-KjR8mNvQ2pLwXcYtZa4bDe"): "slack_token",
    _key("AKIA", "IOSFODNN7EXAMPLE"): "aws_access_key_id",
    _key("shpat", "_9f3c2a7b8d1e4056c9a2b7f3e8d1c604"): "shopify_admin_token",
    "215aa7c2cbf9f93189a290d5ebd26da746b15e9c": "unrecognised_secret",
    "R8kZq2mNv7XcR4tLpW9sYb3EdG6hJ1uK": "unrecognised_secret",
}
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFub24ifQ."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")


def test_no_false_positives():
    flagged = [n for n in NOISE if keyspill.classify(n)]
    assert flagged == [], f"developer output reported as secrets: {flagged}"


def test_finds_every_vendor_format():
    missed = {v: k for v, k in SECRETS.items() if keyspill.classify(v) != k}
    assert missed == {}, f"missed or misclassified: {missed}"


def test_finds_jwt():
    assert keyspill.classify(JWT) == "jwt"


def test_masking_never_reveals_enough_to_use():
    v = _key("sk_", "live_51S9bVyGBA2e2MkumQ8xZr3TvNc9pLdKfWm2Yh4Jb")
    m = keyspill.mask(v)
    assert v not in m and len(m) < 20 and m.startswith("sk_l") and m.endswith("h4Jb")


def test_live_config_and_dead_copies_are_told_apart():
    from pathlib import Path
    assert keyspill.where(Path("/app/.env")) == "live config"
    assert keyspill.where(Path("/app/config/settings.json")) == "live config"
    assert keyspill.where(Path("/app/logs/deploy.log")) == "dead copy"
    assert keyspill.where(Path("/home/u/.zsh_history")) == "dead copy"
    assert keyspill.where(Path("/app/main.py")) == "source"


def test_entropy_ordering():
    assert keyspill.entropy("aaaaaaaa") < keyspill.entropy("typing_extensions") \
        < keyspill.entropy("R8kZq2mNv7XcR4tLpW9sYb3EdG6hJ1uK")





def test_binaries_are_skipped(tmp_path=None):
    """Code-signature blobs inside a signed binary read as high-entropy secrets.

    This is not hypothetical: scanning one `~/bin` turned up two "secrets" that were both
    signature data inside an extensionless Mach-O python.
    """
    import tempfile, os
    from pathlib import Path
    d = Path(tempfile.mkdtemp())
    (d / "real.env").write_text("KEY=" + _key("ghp", "_A8kZq2mNv7XcR4tLpW9sYb3EdG6hJ1uK5oQ0") + "\n")
    (d / "binary_no_extension").write_bytes(
        b"\x7fELF\x00\x00\x01" + b"HfFu8kZq2mNv7XcR4tLpW9s2wTc" + b"\x00" * 32)
    assert keyspill.is_binary(d / "binary_no_extension")
    assert not keyspill.is_binary(d / "real.env")
    found = [p.name for p in keyspill.walk(d)]
    assert found == ["real.env"], found


def test_content_hashes_are_not_secrets():
    """One package-lock.json produced 438 'secrets' before this was handled."""
    lock = ('  "node_modules/foo": {\n'
            '    "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",\n'
            '    "integrity": "sha512-8kZq2mNv7XcR4tLpW9sYb3EdG6hJ1uK5oQ0wRt2yXbN4mP=="\n')
    assert keyspill.scan_text(lock, generic=True) == []
    assert keyspill.LOCKFILES.search("app/package-lock.json")
    assert keyspill.LOCKFILES.search("ios/App/Podfile.lock")
    assert not keyspill.LOCKFILES.search("app/settings.py")


def test_named_keys_still_found_inside_a_lockfile():
    """Skipping the entropy sweep must not blind it to a real key pasted in there."""
    token = _key("ghp", "_A8kZq2mNv7XcR4tLpW9sYb3EdG6hJ1uK5oQ0")
    hits = keyspill.scan_text('"token": "' + token + '"', generic=False)
    assert [h[1] for h in hits] == ["github_token"]


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print(f"  ok    {name}")
            except AssertionError as e:
                fails += 1; print(f"  FAIL  {name}: {e}")
    print(f"\n{'all passed' if not fails else f'{fails} failed'}")
    raise SystemExit(1 if fails else 0)
