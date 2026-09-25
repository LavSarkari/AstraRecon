"""DAG Workflow Definition Schema."""

from typing import Any, Optional
from pydantic import BaseModel, Field


class NodeDefinition(BaseModel):
    """Specification of an individual step or tool in the DAG."""
    id: str
    type: str  # e.g., 'builtin.target_input', 'plugin.subfinder', 'builtin.union_dedupe'
    config: dict[str, Any] = Field(default_factory=dict)


class EdgeDefinition(BaseModel):
    """Connection between output port of source node and input port of target node."""
    source: str
    source_port: str
    target: str
    target_port: str


class WorkflowScope(BaseModel):
    """Scope boundaries and filtering rules for the workflow execution."""
    auto_enforce_root: bool = True
    include_patterns: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=list)


class WorkflowDefinition(BaseModel):
    """Versioned executable workflow representation (.astra format)."""
    schema_version: int = 1
    id: str
    name: str
    description: Optional[str] = None
    scope: WorkflowScope = Field(default_factory=WorkflowScope)
    nodes: list[NodeDefinition] = Field(default_factory=list)
    edges: list[EdgeDefinition] = Field(default_factory=list)
