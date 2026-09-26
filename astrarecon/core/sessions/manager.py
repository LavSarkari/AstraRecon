"""Session lifecycle management, directory coordination, and checkpoint persistence."""

import json
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from astrarecon.core.models.session import (
    CheckpointDescriptor,
    EnvFingerprint,
    NodeExecutionStatus,
    SessionSnapshot,
    SessionStatus,
)
from astrarecon.core.models.workflow import WorkflowDefinition


class SessionManager:
    """Coordinates session lifecycle, disk state, and atomic checkpoints."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or (Path.home() / ".astrarecon" / "sessions")
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def generate_session_id(self, target: str) -> str:
        """Generates a human-readable session ID (e.g. 2026-09-26-001-example-com)."""
        date_str = datetime.utcnow().strftime("%Y-%m-%d")
        safe_target = target.replace(".", "-").replace("/", "").replace(":", "-")
        
        # Check existing sessions for today to compute next sequence number
        existing = list(self.base_dir.glob(f"{date_str}-*-{safe_target}"))
        seq = len(existing) + 1
        return f"{date_str}-{seq:03d}-{safe_target}"

    def get_sessions_for_target(self, target: str) -> list[tuple[Path, SessionSnapshot]]:
        """Returns all existing sessions for a given target domain, sorted newest first."""
        target_clean = target.lower().strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        safe_target = target_clean.replace(".", "-")
        results = []
        if not self.base_dir.exists():
            return results

        seen_dirs = set()
        for sdir in self.base_dir.iterdir():
            if not sdir.is_dir() or sdir.name in seen_dirs:
                continue

            if (sdir / "session.json").exists():
                try:
                    snapshot = self.load_session_snapshot(sdir)
                    snap_target = snapshot.target.lower().strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                    if snap_target == target_clean or safe_target in sdir.name:
                        results.append((sdir, snapshot))
                        seen_dirs.add(sdir.name)
                        continue
                except Exception:
                    pass

            if safe_target in sdir.name and (sdir / "workflow.json").exists():
                try:
                    snap = SessionSnapshot(
                        session_id=sdir.name,
                        target=target,
                        workflow_id=f"scan-{target}",
                        status=SessionStatus.CREATED,
                        created_at=datetime.utcfromtimestamp(sdir.stat().st_ctime),
                        updated_at=datetime.utcfromtimestamp(sdir.stat().st_mtime),
                        node_states={},
                        progress_percentage=0.0,
                    )
                    results.append((sdir, snap))
                    seen_dirs.add(sdir.name)
                except Exception:
                    continue

        results.sort(key=lambda item: item[0].stat().st_mtime, reverse=True)
        return results

    def create_session(
        self,
        target: str,
        workflow: WorkflowDefinition,
        fingerprint: EnvFingerprint,
        session_id: Optional[str] = None,
    ) -> Path:
        """Initializes a new persistent session directory and freezes workflow/fingerprint."""
        sid = session_id or self.generate_session_id(target)
        session_dir = self.base_dir / sid
        session_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        (session_dir / "checkpoints").mkdir(exist_ok=True)
        (session_dir / "artifacts").mkdir(exist_ok=True)
        (session_dir / "logs").mkdir(exist_ok=True)
        (session_dir / "quarantine").mkdir(exist_ok=True)
        (session_dir / "exports" / "ai").mkdir(parents=True, exist_ok=True)

        # Freeze workflow definition
        with open(session_dir / "workflow.json", "w", encoding="utf-8") as f:
            f.write(workflow.model_dump_json(indent=2))

        # Save host environment fingerprint
        with open(session_dir / "fingerprint.json", "w", encoding="utf-8") as f:
            f.write(fingerprint.model_dump_json(indent=2))

        # Initialize session.json
        now = datetime.utcnow()
        node_states = {node.id: NodeExecutionStatus.PENDING for node in workflow.nodes}
        snapshot = SessionSnapshot(
            session_id=sid,
            target=target,
            workflow_id=workflow.id,
            status=SessionStatus.CREATED,
            created_at=now,
            updated_at=now,
            node_states=node_states,
            progress_percentage=0.0,
        )
        self.save_session_snapshot(session_dir, snapshot)

        return session_dir

    def save_session_snapshot(self, session_dir: Path, snapshot: SessionSnapshot) -> None:
        """Atomically saves session.json."""
        snapshot.updated_at = datetime.utcnow()
        tmp_file = session_dir / "session.json.tmp"
        final_file = session_dir / "session.json"
        
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(snapshot.model_dump_json(indent=2))
        tmp_file.replace(final_file)

    def load_session_snapshot(self, session_dir: Path) -> SessionSnapshot:
        """Loads session.json from disk."""
        with open(session_dir / "session.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        return SessionSnapshot.model_validate(data)

    def save_checkpoint(self, session_dir: Path, checkpoint: CheckpointDescriptor) -> None:
        """Persists a completed node checkpoint descriptor."""
        cp_file = session_dir / "checkpoints" / f"{checkpoint.node_id}.json"
        with open(cp_file, "w", encoding="utf-8") as f:
            f.write(checkpoint.model_dump_json(indent=2))

    def load_checkpoints(self, session_dir: Path) -> dict[str, CheckpointDescriptor]:
        """Loads all completed checkpoints for a session."""
        checkpoints = {}
        cp_dir = session_dir / "checkpoints"
        if cp_dir.exists():
            for f in cp_dir.glob("*.json"):
                try:
                    with open(f, "r", encoding="utf-8") as fp:
                        data = json.load(fp)
                    desc = CheckpointDescriptor.model_validate(data)
                    checkpoints[desc.node_id] = desc
                except Exception:
                    continue
        return checkpoints

    def check_environment_drift(self, session_dir: Path, current_fingerprint: EnvFingerprint) -> list[str]:
        """Compares current host environment against session fingerprint to detect tool drift."""
        fp_file = session_dir / "fingerprint.json"
        if not fp_file.exists():
            return []

        try:
            with open(fp_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
            saved_tools = saved.get("tools", {})
        except Exception:
            return []

        drifts = []
        for tool, cur_ver in current_fingerprint.tools.items():
            prev_ver = saved_tools.get(tool)
            if prev_ver and prev_ver != cur_ver:
                drifts.append(f"{tool}: {prev_ver} -> {cur_ver}")

        return drifts

    def delete_session(self, session_id: str) -> bool:
        """Deletes a session directory and all its checkpoints/artifacts."""
        session_dir = self.base_dir / session_id
        if session_dir.exists() and session_dir.is_dir():
            shutil.rmtree(session_dir, ignore_errors=True)
            return True
        return False

    def prune_sessions(
        self,
        older_than_days: int = 7,
        status_filter: Optional[list[SessionStatus]] = None,
    ) -> tuple[int, int]:
        """Prunes sessions matching age or status criteria.
        
        Returns:
            (pruned_count, reclaimed_bytes)
        """
        now = time.time()
        max_age_seconds = older_than_days * 86400
        pruned_count = 0
        reclaimed_bytes = 0

        if not self.base_dir.exists():
            return 0, 0

        for sdir in list(self.base_dir.iterdir()):
            if not sdir.is_dir():
                continue

            session_file = sdir / "session.json"
            snap = None
            if session_file.exists():
                try:
                    snap = self.load_session_snapshot(sdir)
                except Exception:
                    pass

            # Check status filter if provided
            if status_filter and snap and snap.status not in status_filter:
                continue

            # Check age
            mtime = sdir.stat().st_mtime
            if (now - mtime) >= max_age_seconds or (status_filter and snap and snap.status in status_filter):
                dir_size = sum(f.stat().st_size for f in sdir.rglob("*") if f.is_file())
                shutil.rmtree(sdir, ignore_errors=True)
                pruned_count += 1
                reclaimed_bytes += dir_size

        return pruned_count, reclaimed_bytes

    def clear_sessions(self, target: Optional[str] = None) -> tuple[int, int]:
        """Clears all recorded sessions, or sessions matching a specific target domain.
        
        Returns:
            (deleted_count, reclaimed_bytes)
        """
        if not self.base_dir.exists():
            return 0, 0

        deleted_count = 0
        reclaimed_bytes = 0

        for sdir in list(self.base_dir.iterdir()):
            if not sdir.is_dir():
                continue

            session_file = sdir / "session.json"
            if target:
                match = False
                if session_file.exists():
                    try:
                        snap = self.load_session_snapshot(sdir)
                        if snap.target.lower() == target.lower() or target.lower() in sdir.name.lower():
                            match = True
                    except Exception:
                        if target.lower() in sdir.name.lower():
                            match = True
                elif target.lower() in sdir.name.lower():
                    match = True
                if not match:
                    continue

            try:
                dir_size = sum(f.stat().st_size for f in sdir.rglob("*") if f.is_file())
            except Exception:
                dir_size = 0

            shutil.rmtree(sdir, ignore_errors=True)
            deleted_count += 1
            reclaimed_bytes += dir_size

        return deleted_count, reclaimed_bytes
