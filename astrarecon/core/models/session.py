"""Session, Checkpoint, and Environment Fingerprint Schemas."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

from astrarecon.core.models.types import DataType


class NodeExecutionStatus(str, Enum):
    """Execution status for individual DAG nodes."""
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    CANCELLED = "CANCELLED"


class SessionStatus(str, Enum):
    """Top-level lifecycle status for a scan session."""
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    CHECKPOINTED = "CHECKPOINTED"
    COMPLETED = "COMPLETED"
    INTERRUPTED = "INTERRUPTED"
    PAUSED_LOW_DISK = "PAUSED_LOW_DISK"
    FAILED = "FAILED"


class ArtifactRef(BaseModel):
    """Reference to an artifact produced by a node."""
    type: DataType
    path: str
    sha256: str
    line_count: Optional[int] = None
    cas_path: Optional[str] = None


class CheckpointDescriptor(BaseModel):
    """Detailed record of a single node's execution and outputs."""
    node_id: str
    plugin_id: str
    plugin_version: Optional[str] = None
    tool_version: Optional[str] = None
    status: NodeExecutionStatus
    exit_code: Optional[int] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    cache_hit: bool = False
    cache_key: Optional[str] = None
    inputs: dict[str, Any] = Field(default_factory=dict)
    outputs: dict[str, ArtifactRef] = Field(default_factory=dict)
    error_message: Optional[str] = None


class EnvFingerprint(BaseModel):
    """Snapshot of host environment at session initialization."""
    captured_at: datetime
    os_distro: str
    os_version: str
    kernel: str
    arch: str
    python_version: str
    go_version: Optional[str] = None
    tools: dict[str, str] = Field(default_factory=dict)  # tool_name -> detected_version


class SessionSnapshot(BaseModel):
    """Session state descriptor persisted as session.json."""
    session_id: str
    target: str
    workflow_id: str
    status: SessionStatus
    created_at: datetime
    updated_at: datetime
    node_states: dict[str, NodeExecutionStatus] = Field(default_factory=dict)
    progress_percentage: float = 0.0
    error_message: Optional[str] = None
