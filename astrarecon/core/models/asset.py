"""Canonical Asset and Finding Models."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class AssetType(str, Enum):
    """Categorization of discovered attack surface entities."""
    DOMAIN = "DOMAIN"
    FQDN = "FQDN"
    IP = "IP"
    CIDR = "CIDR"
    URL = "URL"
    SERVICE = "SERVICE"


class AssetModel(BaseModel):
    """Deduplicated asset record stored in session state."""
    id: str  # Deterministic hash of asset_type + value
    scan_run_id: str
    asset_type: AssetType
    value: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class FindingSeverity(str, Enum):
    """Normalized vulnerability severity classification."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingModel(BaseModel):
    """Security finding, vulnerability, or exposure."""
    id: str
    scan_run_id: str
    asset_id: Optional[str] = None
    tool_id: str
    severity: FindingSeverity
    title: str
    description: Optional[str] = None
    matcher_name: Optional[str] = None
    curl_poc: Optional[str] = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    cve_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
