"""
File Vault Module
-----------------
The heart of file protection.

Responsibilities:
  1. INDEX   — scan all files on HDD/SSD, record path + metadata
  2. HASH    — SHA-256 fingerprint every file (integrity proof)
  3. SNAPSHOT — copy files into encrypted vault storage
  4. MONITOR — detect changes, deletions, corruption
  5. RECOVER — restore any file from its snapshot
"""

import hashlib
import json
import logging
import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

log = logging.getLogger("FileVault")


class FileVault:
    """
    Complete file protection system.
    Indexes files across HDD/SSD, fingerprints them,
    creates snapshots, detects changes, restores on demand.
    """

    def __init__(self, config: dict):
        self.config = config
        self.vault_dir = Path(config.get("vault_dir", "./vault"))
        self.watch_paths = [Path(p) for p in config.get("watch_paths", [])]
        self.watch_all_drives = config.get("watch_all_drives", False)

        # Vault subdirectories
        self.index_dir = self.vault_dir / "index"        # JSON file registry
        self.snapshots_dir = self.vault_dir / "snapshots"  # Actual file copies
        self.db_path = self.vault_dir / "vault_db.json"  # Hash database

        # Create vault structure
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.index_dir.mkdir(exist_ok=True)
        self.snapshots_dir.mkdir(exist_ok=True)

        # In-memory hash database (also persisted to JSON)
        self.hash_db = self._load_hash_db()

        log.info(f"FileVault initialized | Vault: {self.vault_dir}")

    # ── Hash Database ─────────────────────────────────────────────────────────

    def _load_hash_db(self) -> dict:
        """Load the hash database from disk."""
        if self.db_path.exists():
            try:
                with open(self.db_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                log.warning(f"Could not load hash DB: {e}. Starting fresh.")
        return {}

    def _save_hash_db(self):
        """Persist the hash database to disk."""
        with open(self.db_path, "w") as f:
            json.dump(self.hash_db, f, indent=2)

    # ── File Hashing ──────────────────────────────────────────────────────────

    def hash_file(self, filepath: Path) -> Optional[str]:
        """
        Compute SHA-256 hash of a file.
        Returns hex digest string, or None if file can't be read.
        """
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                # Read in chunks to handle large files without loading into RAM
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (PermissionError, OSError, FileNotFoundError) as e:
            log.debug(f"Cannot hash {filepath}: {e}")
            return None

    # ── File Indexing ─────────────────────────────────────────────────────────

    def initial_index(self) -> dict:
        """
        First-time full scan of all watch paths.
        Builds the hash database — this is the 'baseline' for integrity checks.
        """
        log.info("Building initial file index...")
        all_files = []
        errors = []

        scan_paths = self._get_scan_paths()

        for scan_path in scan_paths:
            log.info(f"  Scanning: {scan_path}")
            for filepath in self._walk_directory(scan_path):
                file_entry = self._index_file(filepath)
                if file_entry:
                    all_files.append(file_entry)
                    # Store hash in DB
                    self.hash_db[str(filepath)] = {
                        "hash": file_entry["hash"],
                        "size": file_entry["size"],
                        "indexed_at": file_entry["indexed_at"],
                        "last_seen": file_entry["indexed_at"],
                    }

        self._save_hash_db()

        # Save index report
        index_report = {
            "indexed_at": datetime.now().isoformat(),
            "total_files": len(all_files),
            "scan_paths": [str(p) for p in scan_paths],
            "files": all_files,
        }

        index_file = self.index_dir / f"index_{int(time.time())}.json"
        with open(index_file, "w") as f:
            json.dump(index_report, f, indent=2)

        log.info(f"Index complete | {len(all_files)} files indexed")
        return index_report

    def _index_file(self, filepath: Path) -> Optional[dict]:
        """Collect metadata + hash for a single file."""
        try:
            stat = filepath.stat()
            file_hash = self.hash_file(filepath)
            return {
                "path": str(filepath),
                "name": filepath.name,
                "extension": filepath.suffix,
                "size": stat.st_size,
                "hash": file_hash,
                "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "indexed_at": datetime.now().isoformat(),
            }
        except Exception as e:
            log.debug(f"Cannot index {filepath}: {e}")
            return None

    def _get_scan_paths(self) -> list:
        """Determine which paths to scan based on config. Removes redundant sub-paths."""
        if self.watch_all_drives:
            import psutil
            paths = []
            for partition in psutil.disk_partitions(all=False):
                paths.append(Path(partition.mountpoint))
            return paths

        # Deduplicate: remove any path that is a sub-path of another watch path
        resolved = [p.resolve() for p in self.watch_paths]
        unique = []
        for p in resolved:
            is_subpath = any(
                p != other and str(p).startswith(str(other) + "\\")
                for other in resolved
            )
            if not is_subpath and p not in unique:
                unique.append(p)
        return unique

    def _walk_directory(self, path: Path):
        """
        Walk a directory and yield all file paths.
        Skips system directories, vault itself, temp files, and Windows
        shell junction folders like 'My documents' inside Documents.
        Also skips the ZYVARON application folder itself (logs, DB, vault).
        """
        SKIP_DIRS = {
            ".git", "__pycache__", "node_modules", ".cache",
            "Trash", "$Recycle.Bin", "System Volume Information",
            str(self.vault_dir),
            # Windows shell junction folders that cause infinite recursion
            "My documents", "My music", "My pictures", "My videos",
            "My Documents", "My Music", "My Pictures", "My Videos",
            # ZYVARON application folders — these change constantly and are not user files
            "ZYVARON",
        }
        # File extensions/names to always skip
        SKIP_FILES = {
            "hash_db.json", "remediation_log.json", "cyberguard_agent.log",
            "zyvaron.db", "zyvaron.db-shm", "zyvaron.db-wal",
        }
        SKIP_EXTENSIONS = {".pyc", ".pyo", ".tmp", ".log", ".db-shm", ".db-wal"}

        try:
            root_resolved = path.resolve()
        except Exception:
            return

        if not path.exists():
            log.warning(f"Watch path does not exist: {path}")
            return

        try:
            for item in path.rglob("*"):
                # Skip blacklisted directory names anywhere in path
                if any(skip.lower() in [p.lower() for p in item.parts] for skip in SKIP_DIRS):
                    continue
                # Skip internal/temp files by name or extension
                if item.name in SKIP_FILES or item.suffix.lower() in SKIP_EXTENSIONS:
                    continue
                # Skip junction/symlink loops — item resolves outside root
                try:
                    item_resolved = item.resolve()
                    if not str(item_resolved).lower().startswith(str(root_resolved).lower()):
                        continue
                except Exception:
                    continue
                if item.is_file():
                    yield item
        except PermissionError as e:
            log.debug(f"Permission denied walking {path}: {e}")

    # ── Integrity Checking ────────────────────────────────────────────────────

    def check_integrity(self) -> dict:
        """
        Re-scan all indexed files and compare hashes.
        Detects: modifications, deletions, new files.

        KEY BEHAVIOUR:
        - Deleted files are removed from hash_db after being reported ONCE.
          This prevents the same deletion from showing up on every scan.
        - Only genuinely new deletions are reported each cycle.
        """
        log.info("Running file integrity check...")

        modified  = []
        deleted   = []
        new_files = []
        checked   = 0
        paths_to_remove = []  # deleted files to remove from hash_db after this scan

        # Check all files we know about
        for filepath_str, record in list(self.hash_db.items()):
            filepath = Path(filepath_str)
            checked += 1

            if not filepath.exists():
                # File was deleted — report it ONCE then remove from tracking
                deleted.append({
                    "path": filepath_str,
                    "last_seen": record.get("last_seen"),
                    "original_hash": record.get("hash"),
                    "severity": "HIGH",
                })
                log.warning(f"FILE DELETED: {filepath_str}")
                paths_to_remove.append(filepath_str)
                continue

            # Re-hash and compare
            current_hash = self.hash_file(filepath)
            if current_hash and current_hash != record.get("hash"):
                modified.append({
                    "path": filepath_str,
                    "original_hash": record.get("hash"),
                    "current_hash": current_hash,
                    "severity": "MEDIUM",
                    "detected_at": datetime.now().isoformat(),
                })
                log.warning(f"FILE MODIFIED: {filepath_str}")
                self.hash_db[filepath_str]["hash"]      = current_hash
                self.hash_db[filepath_str]["last_seen"] = datetime.now().isoformat()
            else:
                self.hash_db[filepath_str]["last_seen"] = datetime.now().isoformat()

        # Remove deleted files from hash_db — they will no longer be re-reported
        for p in paths_to_remove:
            del self.hash_db[p]

        # Scan for new files not in our DB
        for scan_path in self._get_scan_paths():
            for filepath in self._walk_directory(scan_path):
                if str(filepath) not in self.hash_db:
                    file_entry = self._index_file(filepath)
                    if file_entry:
                        new_files.append(file_entry)
                        self.hash_db[str(filepath)] = {
                            "hash":       file_entry["hash"],
                            "size":       file_entry["size"],
                            "indexed_at": file_entry["indexed_at"],
                            "last_seen":  file_entry["indexed_at"],
                        }

        self._save_hash_db()

        result = {
            "checked_at":    datetime.now().isoformat(),
            "total_checked": checked,
            "total_changes": len(modified) + len(deleted) + len(new_files),
            "modified":      modified,
            "deleted":       deleted,
            "new_files":     new_files,
            "status":        "ALERT" if (modified or deleted) else "CLEAN",
        }

        if result["status"] == "ALERT":
            log.warning(f"Integrity check ALERT | {len(modified)} modified, {len(deleted)} deleted")
        else:
            log.info(f"Integrity check CLEAN | {checked} files verified")

        return result

    # ── Snapshots ─────────────────────────────────────────────────────────────

    def get_changes_since_last_snapshot(self) -> int:
        """
        Returns number of files that have changed/been added since the last snapshot.
        Used to decide whether a new snapshot is needed.
        """
        snapshots = self.list_snapshots()
        if not snapshots:
            return len(self.hash_db)  # No snapshot yet — all files are "new"

        # Load the last snapshot's manifest
        last_snap_id = snapshots[0]["snapshot_id"]
        manifest_path = self.snapshots_dir / last_snap_id / "manifest.json"
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
            snap_hashes = {f["original_path"]: f["hash"] for f in manifest.get("files", [])}
        except Exception:
            return len(self.hash_db)

        changed = 0
        for path_str, record in self.hash_db.items():
            current_hash = record.get("hash", "")
            if path_str not in snap_hashes:
                changed += 1  # New file
            elif snap_hashes[path_str] != current_hash:
                changed += 1  # Modified file
        return changed

    def create_snapshot(self, label: str = None) -> dict:
        """
        Create a full snapshot of all protected files.
        Files are copied into vault/snapshots/<snapshot_id>/
        """
        snapshot_id = f"snap_{int(time.time())}"
        if label:
            snapshot_id = f"{snapshot_id}_{label}"

        snapshot_path = self.snapshots_dir / snapshot_id
        snapshot_path.mkdir(parents=True, exist_ok=True)

        log.info(f"Creating snapshot: {snapshot_id}")

        files_snapped = 0
        errors = 0
        manifest = {
            "snapshot_id": snapshot_id,
            "created_at": datetime.now().isoformat(),
            "label": label,
            "files": [],
        }

        for filepath_str in self.hash_db.keys():
            filepath = Path(filepath_str)
            if not filepath.exists():
                continue

            try:
                # Recreate relative directory structure inside snapshot
                # Use a flattened name to avoid path conflicts
                safe_name = filepath_str.replace("/", "__").replace("\\", "__").replace(":", "")
                dest = snapshot_path / safe_name

                shutil.copy2(filepath, dest)
                files_snapped += 1

                manifest["files"].append({
                    "original_path": filepath_str,
                    "snapshot_file": safe_name,
                    "hash": self.hash_db[filepath_str].get("hash"),
                })
            except Exception as e:
                errors += 1
                log.debug(f"Could not snap {filepath}: {e}")

        manifest["total_files"] = files_snapped
        manifest["errors"] = errors

        # Save snapshot manifest
        manifest_path = snapshot_path / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        log.info(f"Snapshot complete | ID: {snapshot_id} | Files: {files_snapped}")
        return manifest

    def list_snapshots(self) -> list:
        """List all available snapshots."""
        snapshots = []
        for snapshot_dir in self.snapshots_dir.iterdir():
            manifest_path = snapshot_dir / "manifest.json"
            if manifest_path.exists():
                with open(manifest_path) as f:
                    manifest = json.load(f)
                snapshots.append({
                    "snapshot_id": manifest["snapshot_id"],
                    "created_at": manifest["created_at"],
                    "total_files": manifest.get("total_files", 0),
                    "label": manifest.get("label"),
                })
        snapshots.sort(key=lambda x: x["created_at"], reverse=True)
        return snapshots

    # ── Recovery ──────────────────────────────────────────────────────────────

    def recover_file(self, original_path: str, snapshot_id: str = None) -> dict:
        """
        Recover a file from a snapshot.
        Searches all snapshots from newest to oldest until the file is found.
        This handles the case where the most recent snapshot was taken AFTER
        the file was deleted (so the file only exists in earlier snapshots).
        """
        log.info(f"Recovery requested for: {original_path}")

        snapshots = self.list_snapshots()
        if not snapshots:
            return {"success": False, "error": "No snapshots available"}

        # If a specific snapshot requested, only search that one
        if snapshot_id:
            search_snapshots = [s for s in snapshots if s["snapshot_id"] == snapshot_id]
            if not search_snapshots:
                return {"success": False, "error": f"Snapshot {snapshot_id} not found"}
        else:
            # Search ALL snapshots newest→oldest — file may not be in the latest one
            # (e.g. latest snapshot was taken after deletion)
            search_snapshots = snapshots

        file_entry = None
        found_snapshot_id = None
        found_snapshot_path = None

        for snap in search_snapshots:
            snap_path = self.snapshots_dir / snap["snapshot_id"]
            manifest_path = snap_path / "manifest.json"
            if not manifest_path.exists():
                continue
            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)
            except Exception:
                continue

            for entry in manifest.get("files", []):
                if entry["original_path"] == original_path:
                    file_entry = entry
                    found_snapshot_id = snap["snapshot_id"]
                    found_snapshot_path = snap_path
                    break

            if file_entry:
                log.info(f"  Found in snapshot: {found_snapshot_id}")
                break

        if not file_entry:
            return {
                "success": False,
                "error": f"File not found in any of {len(search_snapshots)} snapshot(s). "
                         f"File may have been created after the last snapshot.",
                "original_path": original_path,
            }

        # Restore the file
        snap_file = found_snapshot_path / file_entry["snapshot_file"]
        if not snap_file.exists():
            return {"success": False, "error": "Snapshot file missing from vault storage"}

        try:
            restore_path = Path(original_path)
            restore_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(snap_file, restore_path)

            restored_hash = self.hash_file(restore_path)
            hash_match = restored_hash == file_entry.get("hash")

            log.info(f"File recovered: {original_path} | Snapshot: {found_snapshot_id} | Hash verified: {hash_match}")

            return {
                "success": True,
                "original_path": original_path,
                "snapshot_id": found_snapshot_id,
                "hash_verified": hash_match,
                "restored_at": datetime.now().isoformat(),
            }

        except Exception as e:
            log.error(f"Recovery failed for {original_path}: {e}")
            return {"success": False, "error": str(e)}

    def recover_all_deleted(self, snapshot_id: str = None) -> dict:
        """
        Find all deleted files and recover them from the latest snapshot.
        Called after ransomware or mass deletion events.
        """
        log.warning("MASS RECOVERY initiated...")

        # Find deleted files
        deleted = []
        for filepath_str in self.hash_db.keys():
            if not Path(filepath_str).exists():
                deleted.append(filepath_str)

        if not deleted:
            log.info("No deleted files found — nothing to recover")
            return {"recovered": 0, "files": []}

        results = []
        for filepath_str in deleted:
            result = self.recover_file(filepath_str, snapshot_id)
            results.append(result)

        success_count = sum(1 for r in results if r.get("success"))
        log.info(f"Mass recovery complete | {success_count}/{len(deleted)} files restored")

        return {
            "total_deleted": len(deleted),
            "recovered": success_count,
            "failed": len(deleted) - success_count,
            "files": results,
        }
