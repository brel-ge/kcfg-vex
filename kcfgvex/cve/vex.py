"""CycloneDX VEX JSON construction helpers.

Minimal builder for an opinionated subset of CycloneDX VEX 1.6.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Dict, Any
from datetime import datetime, timezone
import json


@dataclass
class VEXEntry:
    cve_id: str
    state: str  # affected | not_affected | under_investigation
    justification: str | None
    detail: str
    component_refs: Iterable[str]


def build_vex(entries: List[VEXEntry], spec_version: str = "1.6") -> Dict[str, Any]:
    vulns: List[Dict[str, Any]] = []
    for e in entries:
        v: Dict[str, Any] = {
            "id": e.cve_id,
            "source": {
                "name": "CVE.org",
                "url": f"https://www.cve.org/CVERecord?id={e.cve_id}",
            },
            "analysis": {
                "state": e.state,
                "detail": e.detail or "",
            },
            "affects": [{"ref": r} for r in e.component_refs],
        }
        if e.justification and e.state == "not_affected":
            v["analysis"]["justification"] = e.justification
        vulns.append(v)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat()},
        "vulnerabilities": vulns,
    }


def save_vex(doc: Dict[str, Any], dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")

    return dest
