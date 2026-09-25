"""Built-in Node Handlers: Normalizer, Scope Guard, Streaming Dedupe, Wildcard Detector, Delta Engine."""

import asyncio
import os
import random
import re
import socket
import string
from pathlib import Path
from typing import Optional, Set
from urllib.parse import urlparse


class BuiltinNodeExecutionError(Exception):
    pass


from astrarecon.core.validation import validate_target


class TargetInputNode:
    """Normalizes raw user input into a canonical target."""

    @staticmethod
    def execute(raw_input: str, output_path: Path) -> str:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        is_valid, canonical, err = validate_target(raw_input)
        if not is_valid:
            raise BuiltinNodeExecutionError(f"Target validation failed: {err}")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(canonical + "\n")

        return canonical


class ScopeGuardNode:
    """Filters discovered assets against scope inclusion/exclusion regexes."""

    @staticmethod
    def execute(
        input_path: Path,
        in_scope_output: Path,
        quarantine_output: Path,
        include_patterns: list[str],
        exclude_patterns: list[str],
    ) -> tuple[int, int]:
        in_scope_output.parent.mkdir(parents=True, exist_ok=True)
        quarantine_output.parent.mkdir(parents=True, exist_ok=True)

        inc_regexes = [re.compile(p, re.IGNORECASE) for p in include_patterns] if include_patterns else []
        exc_regexes = [re.compile(p, re.IGNORECASE) for p in exclude_patterns] if exclude_patterns else []

        in_count = 0
        quarantine_count = 0

        with open(input_path, "r", encoding="utf-8", errors="ignore") as in_f, \
             open(in_scope_output, "w", encoding="utf-8") as out_scope, \
             open(quarantine_output, "a", encoding="utf-8") as out_quar:

            for line in in_f:
                item = line.strip().lower()
                if not item:
                    continue

                # Check exclusions first
                is_excluded = any(r.search(item) for r in exc_regexes)
                if is_excluded:
                    out_quar.write(item + "\n")
                    quarantine_count += 1
                    continue

                # Check inclusions
                if inc_regexes:
                    is_included = any(r.search(item) for r in inc_regexes)
                    if not is_included:
                        out_quar.write(item + "\n")
                        quarantine_count += 1
                        continue

                out_scope.write(item + "\n")
                in_count += 1

        return in_count, quarantine_count


class UnionDedupeNode:
    """Streams and deduplicates multiple input files with partial failure tolerance."""

    @staticmethod
    def execute(input_paths: list[Path], output_path: Path, normalize_lower: bool = True) -> int:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        seen: Set[str] = set()
        count = 0

        with open(output_path, "w", encoding="utf-8") as out_f:
            for path in input_paths:
                if not path or not path.exists():
                    continue

                with open(path, "r", encoding="utf-8", errors="ignore") as in_f:
                    for line in in_f:
                        item = line.strip()
                        if normalize_lower:
                            item = item.lower()
                        if not item:
                            continue

                        if item not in seen:
                            seen.add(item)
                            out_f.write(item + "\n")
                            count += 1

        return count


class WildcardDetectorNode:
    """Issues high-entropy DNS probes to detect wildcard DNS sinkholes."""

    @staticmethod
    async def detect_wildcard(domain: str, probe_count: int = 3) -> Optional[list[str]]:
        """Resolves random non-existent hostnames. Returns wildcard IPs if detected."""
        resolved_ips: list[list[str]] = []

        for _ in range(probe_count):
            rand_prefix = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
            probe_host = f"astrarecon-{rand_prefix}.{domain}"
            try:
                loop = asyncio.get_running_loop()
                # Async DNS resolution using getaddrinfo
                addrinfo = await loop.getaddrinfo(probe_host, None, family=socket.AF_INET)
                ips = sorted(list({info[4][0] for info in addrinfo}))
                if ips:
                    resolved_ips.append(ips)
            except socket.gaierror:
                # Expected for non-wildcard domains
                pass

        # If all probes resolved to identical IP sets, wildcard exists
        if len(resolved_ips) == probe_count and all(ips == resolved_ips[0] for ips in resolved_ips):
            return resolved_ips[0]

        return None


class DeltaEngineNode:
    r"""Computes set difference against a baseline (Current \ Baseline = Added)."""

    @staticmethod
    def execute(current_path: Path, baseline_path: Optional[Path], added_output: Path) -> int:
        added_output.parent.mkdir(parents=True, exist_ok=True)

        baseline_set: Set[str] = set()
        if baseline_path and baseline_path.exists():
            with open(baseline_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    item = line.strip().lower()
                    if item:
                        baseline_set.add(item)

        added_count = 0
        with open(current_path, "r", encoding="utf-8", errors="ignore") as in_f, \
             open(added_output, "w", encoding="utf-8") as out_f:
            for line in in_f:
                item = line.strip().lower()
                if item and item not in baseline_set:
                    out_f.write(item + "\n")
                    added_count += 1

        return added_count
