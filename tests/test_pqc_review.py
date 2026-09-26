"""Pins for docs/PQC_REVIEW.md (ROADMAP Phase 12: post-quantum readiness).

The review's inventory table must not rot: these tests assert the surfaces
the review names still exist in the tree, and that no banned primitive
(MD5/SHA-1 digests, RSA/ECDSA/DH asymmetric primitives) has entered it.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PKG = REPO_ROOT / "rebel_profiler"


def _iter_sources():
    for path in sorted(PKG.rglob("*.py")):
        yield path


# ── no banned primitives anywhere in the package ──────────────────────────

def test_no_md5_or_sha1_digest_use():
    banned = ("hashlib.md5", "hashlib.sha1", "blake2b", "blake2s")
    for path in _iter_sources():
        text = path.read_text(encoding="utf-8")
        for needle in banned:
            assert needle not in text, f"{path.relative_to(REPO_ROOT)} uses {needle}"


def test_no_asymmetric_primitives_enter_the_tree():
    banned_imports = ("import rsa", "import ecdsa", "import cryptography", "import Crypto")
    for path in _iter_sources():
        text = path.read_text(encoding="utf-8")
        for needle in banned_imports:
            assert needle not in text, (
                f"{path.relative_to(REPO_ROOT)} imports {needle} — PQC review §5 "
                "requires new crypto to be reviewed first")


# ── the surfaces the inventory names still exist ──────────────────────────

def test_inventory_surfaces_still_exist():
    expected = {
        "evidence/store.py": "compute_sha256",
        "evidence/audit.py": "sha256",
        "execution/worker.py": "sha256",
        "core/plugins.py": "hmac.new",
        "core/events.py": "hmac.new",
        "security/credentials.py": "scrypt",
        "agent/forge.py": "hmac.new",
        "llm/daemon.py": "sha256",
    }
    for rel, needle in expected.items():
        text = (PKG / rel).read_text(encoding="utf-8")
        assert needle in text, f"PQC inventory surface missing: {rel}::{needle}"


def test_review_document_is_present_and_current():
    doc = (REPO_ROOT / "docs" / "PQC_REVIEW.md").read_text(encoding="utf-8")
    for fragment in ("FIPS 203", "FIPS 204", "FIPS 205", "ML-KEM", "ML-DSA",
                     "SHA-256", "scrypt", "v1.6.1"):
        assert fragment in doc, f"PQC review lost its {fragment} coverage"
    assert "v1.7" not in doc  # re-review due when the version moves past 1.6.x
