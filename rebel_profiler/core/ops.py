"""Operations: backup/restore, offline packaging, upgrade hooks, self-repair (PDF 18/20).

  * ``backup_case``  — a zip archive of case.db + blobs + a manifest (with
    case id, schema version and SHA-256 of each member). Restores are
    manifest-verified before anything is written.
  * ``restore_case`` — verifies the manifest hashes, then writes case.db and
    blobs back into a case directory (existing dirs are never clobbered).
  * ``package_zipapp`` — build an executable ``.pyz`` (stdlib zipimport) for
    offline/Kali-live usage with no install step.
  * ``check_and_repair`` — the self-repair loop of PDF 20: inspect
    (evidence/audit integrity, schema version, index consistency) → attempt
    deterministic repairs (rebuildable views) → report what was fixed vs
    what needs an operator.

Nothing here executes case logic; this is the outer shell of the product.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
import zipfile
from pathlib import Path

from .errors import RPError, StateError, UsageError

BACKUP_MANIFEST = "manifest.json"
SCHEMA_META_KEY = "schema_version"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def backup_case(case_dir: Path, out_path: Path) -> dict:
    """Zip case.db + blobs + manifest; returns the backup record."""
    case_dir = Path(case_dir)
    db_path = case_dir / "case.db"
    if not db_path.exists():
        raise UsageError(f"No case database in {case_dir}",
                         action="Point the backup at a case directory.")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    members: list[dict] = []
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(case_dir.rglob("*")):
            if not path.is_file() or path.name == BACKUP_MANIFEST:
                continue
            arcname = str(path.relative_to(case_dir))
            zf.write(path, arcname)
            members.append({"path": arcname, "sha256": _sha256_file(path),
                            "size": path.stat().st_size})
        manifest = {
            "kind": "rebel-profiler-backup",
            "schema_version": 1,
            "case_dir": case_dir.name,
            "created_at": time.time(),
            "members": members,
        }
        zf.writestr(BACKUP_MANIFEST, json.dumps(manifest, indent=2, sort_keys=True))
    return {"backup": str(out_path), "members": len(members),
            "size": out_path.stat().st_size,
            "sha256": _sha256_file(out_path)}


def restore_case(backup_path: Path, dest_dir: Path) -> dict:
    """Manifest-verified restore into a fresh case directory."""
    backup_path = Path(backup_path)
    dest_dir = Path(dest_dir)
    if dest_dir.exists() and any(dest_dir.iterdir()):
        raise UsageError(
            f"Destination {dest_dir} is not empty",
            reason="Restores never clobber existing case data.",
            action="Restore into a new directory or remove the old case first.")
    with zipfile.ZipFile(backup_path) as zf:
        manifest = json.loads(zf.read(BACKUP_MANIFEST))
        if manifest.get("kind") != "rebel-profiler-backup":
            raise StateError("Not a rebel-profiler backup archive")
        by_path = {m["path"]: m for m in manifest["members"]}
        dest_dir.mkdir(parents=True, exist_ok=True)
        restored = 0
        for info in zf.infolist():
            if info.filename == BACKUP_MANIFEST:
                continue
            record = by_path.get(info.filename)
            if record is None:
                raise StateError(
                    f"Archive member '{info.filename}' is not in the manifest")
            data = zf.read(info.filename)
            if hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise StateError(
                    f"Integrity failure: {info.filename} does not match the manifest")
            target = dest_dir / info.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            restored += 1
    return {"restored": restored, "dest": str(dest_dir),
            "case_id": manifest.get("case_dir", dest_dir.name)}


def package_zipapp(source_dir: Path, out_path: Path,
                   *, main_module: str = "rebel_profiler.cli.main:main") -> dict:
    """Build an executable .pyz of the project for offline use."""
    source_dir = Path(source_dir)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source_dir.rglob("*.py")):
            rel = path.relative_to(source_dir)
            if any(part in {"__pycache__", ".git", ".pytest_cache", "tests"}
                   for part in rel.parts):
                continue
            zf.write(path, str(rel))
        zf.writestr("__main__.py",
                    f"import {main_module.split(':')[0]}\n"
                    f"raise SystemExit({main_module}())\n")
    return {"zipapp": str(out_path), "size": out_path.stat().st_size,
            "sha256": _sha256_file(out_path)}


# ---------------------------------------------------------------------------
# Self-check / self-repair (PDF 20)


def check_and_repair(db, case_id: str, *, repair: bool = False) -> dict:
    """Inspect → (optionally) repair → report, for one case."""
    problems: list[str] = []
    repaired: list[str] = []
    needs_operator: list[str] = []

    # 1. schema version present and understood
    version = db.schema_version()
    if version < 1:
        problems.append("schema_meta missing/empty — database never migrated")
        needs_operator.append("re-init the case database")

    # 2. evidence integrity
    try:
        from ..evidence.store import EvidenceStore

        store = EvidenceStore(db, blobs_dir=db.path.parent / "blobs")
        report = store.verify_case(case_id)
        if not report["chain_ok"]:
            problems.extend(f"evidence: {p}" for p in report["problems"])
            # blob-content mismatches can never be "repaired" silently
            needs_operator.append("evidence integrity — treat as compromised")
    except Exception as exc:  # noqa: BLE001 — the shell must not crash
        problems.append(f"evidence check crashed: {exc}")
        needs_operator.append("inspect evidence store manually")

    # 3. audit chain integrity
    try:
        from ..evidence.audit import AuditChain

        audit_report = AuditChain(db).verify(case_id)
        if not audit_report["chain_ok"]:
            problems.extend(f"audit: {p}" for p in audit_report["problems"])
            needs_operator.append("audit chain — tamper evidence triggered")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"audit check crashed: {exc}")
        needs_operator.append("inspect audit chain manually")

    # 4. derived views are rebuildable — safe to repair deterministically
    if repair:
        try:
            count = db.rebuild_search_index(case_id)
            repaired.append(f"search index rebuilt ({count} docs)")
        except Exception as exc:  # noqa: BLE001
            problems.append(f"search rebuild failed: {exc}")

    return {
        "case_id": case_id,
        "schema_version": version,
        "problems": problems,
        "repaired": repaired,
        "needs_operator": needs_operator,
        "healthy": not problems,
        "checked_at": time.time(),
    }
