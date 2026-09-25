"""Unit tests for Target Validation, Error Handling, and Resource Safeguards."""

import tempfile
from pathlib import Path
import pytest

from astrarecon.core.execution.nodes.builtins import BuiltinNodeExecutionError, TargetInputNode
from astrarecon.core.models.session import EnvFingerprint, SessionStatus
from astrarecon.core.models.workflow import NodeDefinition, WorkflowDefinition
from astrarecon.core.sessions.manager import SessionManager
from astrarecon.core.validation import check_disk_space, validate_target


def test_validate_target_valid_domains():
    """Verify valid domain formats are accepted and normalized."""
    test_cases = [
        ("example.com", "example.com"),
        ("SUB.EXAMPLE.COM", "sub.example.com"),
        ("https://example.com/api/v1", "example.com"),
        ("http://test.target.io:8080", "test.target.io"),
        ("*.example.com", "example.com"),
        ("192.168.1.1", "192.168.1.1"),
        ("10.0.0.0/24", "10.0.0.0/24"),
    ]
    for raw, expected in test_cases:
        is_valid, normalized, err = validate_target(raw)
        assert is_valid is True, f"Failed on '{raw}': {err}"
        assert normalized == expected
        assert err is None


def test_validate_target_invalid_inputs():
    """Verify malformed or dangerous target inputs are rejected with clear reasons."""
    invalid_cases = [
        "",
        "   ",
        "example .com",
        "example.com; id",
        "example.com | whoami",
        "http://",
        "https:///api",
        "example..com",
        "singleword",
        "12345",
        "example.com:99999",  # Port out of range
        "-example.com",
        "example-.com",
    ]
    for raw in invalid_cases:
        is_valid, normalized, err = validate_target(raw)
        assert is_valid is False, f"Expected invalid for '{raw}', got valid"
        assert err is not None
        assert len(err) > 0


def test_check_disk_space():
    """Verify disk space check returns valid metrics."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        has_space, free_mb = check_disk_space(Path(tmp_dir), min_mb=10.0)
        assert has_space is True
        assert free_mb > 0.0


def test_target_input_node_validation():
    """Verify TargetInputNode enforces target validation."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = Path(tmp_dir) / "target.txt"

        # Valid domain succeeds
        canonical = TargetInputNode.execute("https://Example.Com/test", out_path)
        assert canonical == "example.com"
        assert out_path.read_text().strip() == "example.com"

        # Invalid domain raises BuiltinNodeExecutionError
        with pytest.raises(BuiltinNodeExecutionError):
            TargetInputNode.execute("example .com", out_path)


def test_session_manager_delete_and_prune():
    """Verify SessionManager deletion and pruning capabilities."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        mgr = SessionManager(base_dir=Path(tmp_dir))

        wf = WorkflowDefinition(
            id="test-wf",
            name="Test Workflow",
            nodes=[NodeDefinition(id="target_input", type="builtin.target_input")],
            edges=[],
        )
        fp = EnvFingerprint(
            captured_at="2026-09-26T00:00:00",
            os_distro="Linux",
            os_version="1.0",
            kernel="test",
            arch="x86_64",
            python_version="3.11",
            go_version="1.22",
            tools={},
        )

        # Create session
        s_dir = mgr.create_session("example.com", wf, fp, session_id="test-session-001")
        assert s_dir.exists()

        # Delete session
        deleted = mgr.delete_session("test-session-001")
        assert deleted is True
        assert not s_dir.exists()

        # Deleting non-existent session returns False
        assert mgr.delete_session("non-existent-session") is False

        # Create multiple sessions for prune testing
        s_dir1 = mgr.create_session("example.com", wf, fp, session_id="test-session-prune-1")
        s_dir2 = mgr.create_session("example.com", wf, fp, session_id="test-session-prune-2")

        # Mark s_dir2 as FAILED
        snap2 = mgr.load_session_snapshot(s_dir2)
        snap2.status = SessionStatus.FAILED
        mgr.save_session_snapshot(s_dir2, snap2)

        # Prune only failed sessions
        count, reclaimed = mgr.prune_sessions(status_filter=[SessionStatus.FAILED])
        assert count == 1
        assert not s_dir2.exists()
        assert s_dir1.exists()
