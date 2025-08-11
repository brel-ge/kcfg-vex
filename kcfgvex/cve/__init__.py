"""
kcfgvex.cve
===========

Subpackage for CVE-related utilities:
- Downloading CVE JSON records from CVE.org
- Saving them to disk
- Future: NVD support, patch extraction, mapping to kernel files
"""

from .fetch import (
    fetch_cve_cveorg,
    fetch_many_cveorg,
    save_cve_json,
)

__all__ = [
    "fetch_cve_cveorg",
    "fetch_many_cveorg",
    "save_cve_json",
]
