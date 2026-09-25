"""Content-Addressed Storage (CAS) and Freshness-Aware Cache."""

import hashlib
import json
import shutil
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


class ContentAddressedStore:
    """Manages immutable file blobs keyed by SHA256 and freshness cache indices."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or (Path.home() / ".astrarecon" / "cache")
        self.blobs_dir = self.base_dir / "blobs"
        self.blobs_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.base_dir / "index.sqlite"
        self._init_db()

    def _init_db(self) -> None:
        """Initializes SQLite cache index in WAL mode."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_entries (
                    cache_key TEXT PRIMARY KEY,
                    plugin_id TEXT NOT NULL,
                    plugin_version TEXT NOT NULL,
                    tool_version TEXT,
                    artifact_sha256 TEXT NOT NULL,
                    blob_path TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    line_count INTEGER DEFAULT 0
                );
            """)
            conn.commit()

    @staticmethod
    def calculate_file_sha256(path: Path) -> str:
        """Calculates the SHA256 digest of a file in streaming chunks."""
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def compute_cache_key(
        plugin_id: str,
        plugin_version: str,
        tool_version: Optional[str],
        config_dict: dict,
        input_artifact_hash: str,
    ) -> str:
        """Calculates unique execution cache key:
        SHA256(plugin_id || plugin_version || tool_version || config_hash || input_hash)
        """
        hasher = hashlib.sha256()
        hasher.update(plugin_id.encode())
        hasher.update(b"::")
        hasher.update(plugin_version.encode())
        hasher.update(b"::")
        hasher.update((tool_version or "none").encode())
        hasher.update(b"::")
        config_json = json.dumps(config_dict, sort_keys=True)
        hasher.update(config_json.encode())
        hasher.update(b"::")
        hasher.update(input_artifact_hash.encode())
        return hasher.hexdigest()

    def put_blob(self, file_path: Path) -> tuple[str, Path]:
        """Stores a file in the CAS blob store.
        
        Returns (sha256, destination_path).
        """
        sha256 = self.calculate_file_sha256(file_path)
        # Store in two-level prefix directory: blobs/4a/1f7c...
        target_dir = self.blobs_dir / sha256[:2]
        target_dir.mkdir(exist_ok=True)
        target_file = target_dir / sha256

        if not target_file.exists():
            shutil.copy2(file_path, target_file)

        return sha256, target_file

    def record_cache_entry(
        self,
        cache_key: str,
        plugin_id: str,
        plugin_version: str,
        tool_version: Optional[str],
        artifact_file: Path,
        ttl_hours: int = 24,
    ) -> tuple[str, Path]:
        """Commits an execution output to the blob store and updates cache index."""
        sha256, blob_path = self.put_blob(artifact_file)
        
        # Count lines if text
        line_count = 0
        try:
            with open(artifact_file, "r", encoding="utf-8", errors="ignore") as f:
                line_count = sum(1 for _ in f)
        except Exception:
            pass

        now = datetime.utcnow()
        expires_at = now + timedelta(hours=ttl_hours)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO cache_entries 
                (cache_key, plugin_id, plugin_version, tool_version, artifact_sha256, blob_path, created_at, expires_at, line_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cache_key,
                plugin_id,
                plugin_version,
                tool_version,
                sha256,
                str(blob_path),
                now.isoformat(),
                expires_at.isoformat(),
                line_count,
            ))
            conn.commit()

        return sha256, blob_path

    def lookup_cache(self, cache_key: str) -> Optional[tuple[str, Path, int]]:
        """Checks if a valid, unexpired cache entry exists for the given key.
        
        Returns (artifact_sha256, blob_path, line_count) or None.
        """
        now = datetime.utcnow().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT artifact_sha256, blob_path, line_count, expires_at
                FROM cache_entries
                WHERE cache_key = ?
            """, (cache_key,))
            row = cursor.fetchone()

        if not row:
            return None

        sha256, blob_str, line_count, expires_at_str = row
        blob_path = Path(blob_str)

        # Check TTL and physical existence
        if expires_at_str < now or not blob_path.exists():
            return None

        return sha256, blob_path, line_count
