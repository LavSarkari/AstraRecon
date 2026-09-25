"""Plugin Manifest Pydantic Specification."""

from typing import Any, Optional
from pydantic import BaseModel, Field

from astrarecon.core.models.types import DataType


class PluginBinary(BaseModel):
    """External binary detection and verification configuration."""
    name: str
    check_args: list[str] = Field(default_factory=lambda: ["-version"])
    version_regex: str = r"v?([0-9]+\.[0-9]+(\.[0-9]+)?)"
    default_path: Optional[str] = None
    install_recipe: Optional[dict[str, Any]] = None


class InputPort(BaseModel):
    """Specification of an incoming data port."""
    name: str
    type: DataType
    required: bool = True
    source: str = "param"  # 'param' (CLI argument string) or 'artifact' (file stream)
    description: Optional[str] = None


class OutputPort(BaseModel):
    """Specification of an outgoing data port."""
    name: str
    type: DataType
    format: str = "text_lines"  # 'text_lines', 'jsonl', 'json', 'binary'
    filename: str
    description: Optional[str] = None


class PluginExecution(BaseModel):
    """Command execution vector and process constraints."""
    command: str
    args: list[str] = Field(default_factory=list)
    timeout_seconds: int = 600
    retry_count: int = 1


class CachePolicyConfig(BaseModel):
    """Freshness and artifact caching policy."""
    policy: str = "fresh"  # 'fresh', 'none', 'immutable'
    default_ttl_hours: int = 24


class PluginManifest(BaseModel):
    """Root declarative plugin manifest schema."""
    schema_version: int = 1
    id: str
    name: str
    plugin_version: str = "1.0.0"  # Version of the AstraRecon wrapper
    stage: str
    description: str
    author: Optional[str] = None
    binary: PluginBinary
    inputs: list[InputPort] = Field(default_factory=list)
    outputs: list[OutputPort] = Field(default_factory=list)
    execution: PluginExecution
    cache: CachePolicyConfig = Field(default_factory=CachePolicyConfig)
