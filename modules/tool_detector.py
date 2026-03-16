"""
modules/tool_detector.py
Cross-references installed packages AND filesystem paths against the PMGP
tool signature dictionary.
Supports both dpkg (Debian/Kali) and pacman (Arch/BlackArch) backends.
Also performs a direct binary/path scan so tools installed outside the
package manager (git clones, manual drops, USB payloads) are caught.
No binaries are executed; only metadata files are read.
"""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Path to the bundled signature dictionary
_DATA_DIR = Path(__file__).parent.parent / "data"
_SIGNATURES_PATH = _DATA_DIR / "tool_signatures.json"


@dataclass
class DetectedTool:
    name: str
    risk_level: str           # "high_risk" | "dual_use" | "anonymization"
    matched_package: str      # package name OR filesystem path
    description: str
    mitre_technique: str
    category: str
    detection_method: str = "package_db"  # "package_db" | "filesystem" | "config"


@dataclass
class ToolDetectionResult:
    detected_tools:       list[DetectedTool] = field(default_factory=list)
    total_packages_scanned: int = 0
    raw_package_list:     list[str] = field(default_factory=list)
    filesystem_hits:      list[str] = field(default_factory=list)  # paths found
    config_hits:          list[str] = field(default_factory=list)  # config traces

    @property
    def by_risk(self) -> dict[str, list[DetectedTool]]:
        result: dict[str, list[DetectedTool]] = {
            "high_risk": [], "dual_use": [], "anonymization": [],
        }
        for t in self.detected_tools:
            result[t.risk_level].append(t)
        return result

    @property
    def risk_counts(self) -> dict[str, int]:
        counts = {"high_risk": 0, "dual_use": 0, "anonymization": 0}
        for t in self.detected_tools:
            counts[t.risk_level] += 1
        return counts


# ── Public entry-point ────────────────────────────────────────────────────────

def detect_tools(
    root_path: str,
    pkg_db_type: str,
    pkg_db_path: Optional[str] = None,
    signatures_path: Optional[str] = None,
) -> ToolDetectionResult:
    """
    Detect offensive / suspicious tools installed on a system image.

    Two detection passes are run:
      1. Package database cross-reference (dpkg / pacman)
      2. Direct filesystem binary path scan (catches non-packaged installs)
      3. Configuration file trace scan (e.g. torrc, proxychains.conf)
    """
    sigs = _load_signatures(signatures_path or str(_SIGNATURES_PATH))
    root_path = root_path.rstrip("/")

    # ── Pass 1: Package database ──────────────────────────────────────────
    if pkg_db_type == "dpkg":
        installed = _read_dpkg_packages(root_path, pkg_db_path)
    elif pkg_db_type == "pacman":
        installed = _read_pacman_packages(root_path, pkg_db_path)
    else:
        installed = set()

    result = ToolDetectionResult(
        total_packages_scanned=len(installed),
        raw_package_list=sorted(installed),
    )

    already_found: set[str] = set()   # avoid duplicating the same tool

    for risk_level, tools in sigs.items():
        for tool_name, meta in tools.items():
            for pkg_variant in meta.get("packages", []):
                if pkg_variant.lower() in installed:
                    result.detected_tools.append(DetectedTool(
                        name=tool_name,
                        risk_level=risk_level,
                        matched_package=pkg_variant,
                        description=meta.get("description", ""),
                        mitre_technique=meta.get("mitre_technique", ""),
                        category=meta.get("category", ""),
                        detection_method="package_db",
                    ))
                    already_found.add(tool_name)
                    break

    # ── Pass 2: Filesystem binary path scan ───────────────────────────────
    for risk_level, tools in sigs.items():
        for tool_name, meta in tools.items():
            if tool_name in already_found:
                continue
            binary_paths = meta.get("binary_paths", [])
            for rel_path in binary_paths:
                full_path = os.path.join(root_path, rel_path.lstrip("/"))
                if os.path.exists(full_path):
                    result.filesystem_hits.append(full_path)
                    result.detected_tools.append(DetectedTool(
                        name=tool_name,
                        risk_level=risk_level,
                        matched_package=rel_path,
                        description=meta.get("description", "") + " [filesystem path]",
                        mitre_technique=meta.get("mitre_technique", ""),
                        category=meta.get("category", ""),
                        detection_method="filesystem",
                    ))
                    already_found.add(tool_name)
                    break

    # ── Pass 3: Configuration file trace scan ─────────────────────────────
    for risk_level, tools in sigs.items():
        for tool_name, meta in tools.items():
            config_traces = meta.get("config_traces", [])
            for rel_path in config_traces:
                full_path = os.path.join(root_path, rel_path.lstrip("/"))
                if os.path.exists(full_path):
                    result.config_hits.append(full_path)
                    if tool_name not in already_found:
                        result.detected_tools.append(DetectedTool(
                            name=tool_name,
                            risk_level=risk_level,
                            matched_package=rel_path,
                            description=meta.get("description", "") + " [config trace]",
                            mitre_technique=meta.get("mitre_technique", ""),
                            category=meta.get("category", ""),
                            detection_method="config",
                        ))
                        already_found.add(tool_name)
                    break  # one config hit is enough per tool

    return result


# ── Package list readers ──────────────────────────────────────────────────────

def _read_dpkg_packages(root: str, explicit_path: Optional[str]) -> set[str]:
    status_path = explicit_path or f"{root}/var/lib/dpkg/status"
    content = _safe_read(status_path, max_bytes=10_000_000)
    if not content and os.path.isdir(status_path):
        content = ""
        try:
            for fname in os.listdir(status_path):
                content += _safe_read(os.path.join(status_path, fname))
        except OSError:
            pass
    return _parse_dpkg_names(content)


def _read_pacman_packages(root: str, explicit_path: Optional[str]) -> set[str]:
    db_dir = explicit_path or f"{root}/var/lib/pacman/local"
    names: set[str] = set()
    if not os.path.isdir(db_dir):
        return names
    try:
        for entry in os.listdir(db_dir):
            desc_path = os.path.join(db_dir, entry, "desc")
            content = _safe_read(desc_path, max_bytes=2048)
            pkg_name = _parse_pacman_name(content)
            if pkg_name:
                names.add(pkg_name)
    except OSError:
        pass
    return names


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_dpkg_names(content: str) -> set[str]:
    names: set[str] = set()
    for line in content.splitlines():
        if line.startswith("Package:"):
            names.add(line.split(":", 1)[1].strip().lower())
    return names


def _parse_pacman_name(desc_content: str) -> Optional[str]:
    lines = desc_content.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "%NAME%":
            if i + 1 < len(lines):
                return lines[i + 1].strip().lower()
    return None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_read(path: str, max_bytes: int = 4096) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(max_bytes)
    except OSError:
        return ""


def _load_signatures(path: str) -> dict:
    with open(path, "r") as fh:
        return json.load(fh)
