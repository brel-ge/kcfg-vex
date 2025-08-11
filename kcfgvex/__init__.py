"""
kcfgvex — Kernel Config & VEX Utilities

This package helps:
- Trace Linux Kbuild/Kconfig dependencies for specific source files.
- Correlate CVE metadata (e.g., CVE Services 5.x, Yocto cve-check) with kernel configuration.
- Emit VEX documents (CycloneDX VEX, OpenVEX) for filtered results.
- Assist with automated patch planning & application for kernel CVEs.

Public API:
    from kcfgvex import __version__
    from kcfgvex.kernel import kbuild_trace, dotconfig
    from kcfgvex.cve import cve_org, nvd
    from kcfgvex.yocto import cve_check
    from kcfgvex.vex import cyclonedx, openvex
    from kcfgvex.patch import kernel_git, backport
"""

__version__ = "0.1.0"

# Re-export commonly used modules/classes for convenience
from .kernel import kbuild_trace, dotconfig
from .cve import fetch  # cve_org, nvd
# from .yocto import cve_check
# from .vex import cyclonedx, openvex
# from .patch import kernel_git, backport

__all__ = [
    "__version__",
    "kbuild_trace",
    "dotconfig",
    "fetch",
    # "cve_org",
    # "nvd",
    # "cve_check",
    # "cyclonedx",
    # "openvex",
    # "kernel_git",
    # "backport",
]
