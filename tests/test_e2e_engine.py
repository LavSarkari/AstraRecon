"""End-to-End Integration Tests for AstraRecon Engine: DAG Execution, Checkpointing, and CAS."""

import asyncio
from pathlib import Path
import pytest

from astrarecon.core.cache.cas import ContentAddressedStore
from astrarecon.core.doctor.inspector import EnvironmentInspector
from astrarecon.core.execution.runner import ExecutionEngine
from astrarecon.core.models.session import NodeExecutionStatus, SessionStatus
from astrarecon.core.models.workflow import EdgeDefinition, NodeDefinition, WorkflowDefinition
from astrarecon.core.plugins.loader import PluginLoader
from astrarecon.core.reports.ai_export import AIDistillationEngine
from astrarecon.core.sessions.manager import SessionManager


@pytest.mark.asyncio
async def test_end_to_end_dag_execution(tmp_path: Path):
    """Executes a complete DAG workflow with TargetInput, ScopeGuard, UnionDedupe, and DeltaEngine."""
    cas = ContentAddressedStore(base_dir=tmp_path / "cache")
    session_mgr = SessionManager(base_dir=tmp_path / "sessions")
    plugin_registry = PluginLoader.load_all_plugins()

    # Define a clean test DAG using built-in nodes
    wf = WorkflowDefinition(
        id="e2e-test",
        name="E2E Built-in Test",
        nodes=[
            NodeDefinition(id="target", type="builtin.target_input", config={"raw_input": "https://sub.example.com:8443/login"}),
            NodeDefinition(id="scope", type="builtin.scope_guard", config={}),
            NodeDefinition(id="dedupe", type="builtin.union_dedupe", config={}),
            NodeDefinition(id="delta", type="builtin.delta_engine", config={}),
        ],
        edges=[
            EdgeDefinition(source="target", source_port="output", target="scope", target_port="input"),
            EdgeDefinition(source="scope", source_port="in_scope", target="dedupe", target_port="inputs"),
            EdgeDefinition(source="dedupe", source_port="output", target="delta", target_port="current_assets"),
        ],
    )

    env = EnvironmentInspector.inspect()
    fingerprint = env  # Mock fingerprint
    from astrarecon.core.models.session import EnvFingerprint
    from datetime import datetime
    fp = EnvFingerprint(
        captured_at=datetime.utcnow(),
        os_distro=env.os_name,
        os_version=env.os_version,
        kernel=env.kernel,
        arch=env.arch,
        python_version=env.python_version,
        tools={},
    )

    session_dir = session_mgr.create_session(target="sub.example.com", workflow=wf, fingerprint=fp)
    assert (session_dir / "workflow.json").exists()
    assert (session_dir / "session.json").exists()

    engine = ExecutionEngine(
        workflow=wf,
        session_dir=session_dir,
        plugin_registry=plugin_registry,
        cas=cas,
        session_manager=session_mgr,
        max_concurrent_workers=2,
    )

    snapshot = await engine.run(resume=False)
    assert snapshot.status == SessionStatus.COMPLETED
    assert snapshot.progress_percentage == 100.0

    # Verify checkpoints were written
    checkpoints = session_mgr.load_checkpoints(session_dir)
    assert len(checkpoints) == 4
    for nid in ["target", "scope", "dedupe", "delta"]:
        assert nid in checkpoints
        assert checkpoints[nid].status == NodeExecutionStatus.COMPLETED

    # Verify TargetInput normalized the dirty URL correctly
    target_cp = checkpoints["target"]
    target_out_path = Path(target_cp.outputs["output"].path)
    with open(target_out_path, "r") as f:
        content = f.read().strip()
    assert content == "sub.example.com"

    # Verify CAS cached the output
    assert target_cp.outputs["output"].sha256 != ""

    # Test AI export generation
    ai_dir = AIDistillationEngine.export_bundle(
        target="sub.example.com",
        session_dir=session_dir,
        output_dir=session_dir / "exports",
    )
    assert (ai_dir / "context.json").exists()
    assert (ai_dir / "findings.json").exists()
    assert (ai_dir / "js_manifest.json").exists()
    assert (ai_dir / "prompt.md").exists()
