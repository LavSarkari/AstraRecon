"""Input validation, target sanitization, and system resource verification."""

import ipaddress
import re
import shutil
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

# Prohibited shell characters that must never appear in targets
PROHIBITED_CHARS = set(";&|><$`'\"\\!*?(){}[]\t\r\n ")

# RFC-compliant domain regex (labels 1-63 chars, letters/digits/hyphens, no leading/trailing hyphen)
DOMAIN_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")


def validate_target(raw_input: Optional[str]) -> Tuple[bool, str, Optional[str]]:
    """Validates and normalizes target specifications (domain, URL, IP, CIDR, or wildcard).
    
    Returns:
        (is_valid, normalized_target, error_message)
    """
    if not raw_input or not raw_input.strip():
        return False, "", "Target cannot be empty"

    target = raw_input.strip()

    # Disallow whitespace anywhere in the target string
    if any(c.isspace() for c in target):
        return False, "", f"Target contains invalid spaces: '{target}'"

    # Check for shell metacharacters (excluding wildcard prefix *. which is handled separately)
    test_chars = target
    if test_chars.startswith("*."):
        test_chars = test_chars[2:]

    if any(c in PROHIBITED_CHARS - set("*") for c in test_chars):
        bad_chars = [c for c in test_chars if c in PROHIBITED_CHARS - set("*")]
        return False, "", f"Target contains prohibited shell characters: {', '.join(repr(c) for c in bad_chars)}"

    # If it's a URL, extract hostname
    if target.startswith("http://") or target.startswith("https://"):
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname
            if not hostname:
                return False, "", f"URL '{target}' does not specify a valid hostname"
            target = hostname
        except Exception as e:
            return False, "", f"Malformed URL '{target}': {e}"

    # Strip port if present (e.g. example.com:8443 or 192.168.1.1:8080)
    if ":" in target and not target.startswith("["):
        parts = target.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            port = int(parts[1])
            if not (1 <= port <= 65535):
                return False, "", f"Port number out of range: {port}"
            target = parts[0]

    # Handle wildcard prefix
    is_wildcard = False
    if target.startswith("*."):
        is_wildcard = True
        target = target[2:]

    # Check for IP address or CIDR notation
    if "/" in target:
        # Possible CIDR
        try:
            network = ipaddress.ip_network(target, strict=False)
            return True, str(network), None
        except ValueError as e:
            return False, "", f"Invalid CIDR network specification '{target}': {e}"

    try:
        ip = ipaddress.ip_address(target)
        return True, str(ip), None
    except ValueError:
        pass  # Not an IP address, proceed with domain validation

    # Validate FQDN / Domain Name syntax
    target_lower = target.lower()

    if ".." in target_lower:
        return False, "", f"Domain contains consecutive dots: '{target}'"

    labels = target_lower.split(".")
    if len(labels) < 2:
        return False, "", f"Domain must contain at least a name and TLD (e.g. example.com), got '{target}'"

    # Validate each label
    for label in labels:
        if not label:
            return False, "", f"Domain contains empty label: '{target}'"
        if len(label) > 63:
            return False, "", f"Domain label '{label}' exceeds maximum length of 63 characters"
        if not DOMAIN_LABEL_REGEX.match(label):
            return False, "", f"Domain label '{label}' contains invalid characters or leading/trailing hyphens"

    # TLD cannot be purely numeric
    if labels[-1].isdigit():
        return False, "", f"TLD '{labels[-1]}' cannot be purely numeric"

    # If it was a wildcard domain, restore canonical domain without *. prefix for scanners
    canonical = target_lower

    return True, canonical, None


def check_disk_space(path: Path, min_mb: float = 200.0) -> Tuple[bool, float]:
    """Checks whether the filesystem hosting `path` has at least `min_mb` available space.
    
    Returns:
        (has_enough_space, available_mb)
    """
    try:
        check_dir = path if path.exists() else path.parent
        if not check_dir.exists():
            check_dir = Path.home()

        total, used, free = shutil.disk_usage(check_dir)
        free_mb = free / (1024 * 1024)
        return (free_mb >= min_mb), free_mb
    except Exception:
        # Fallback if disk usage query fails on certain virtualized filesystems
        return True, 9999.0
