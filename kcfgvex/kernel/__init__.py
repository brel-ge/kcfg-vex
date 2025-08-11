"""
kcfgvex.kernel — Linux kernel helpers

- kbuild_trace: Trace which Kconfig symbols enable building specific source files.
- dotconfig:    Parse and query a built kernel's .config (enabled =y/=m).
"""

from . import kbuild_trace, dotconfig

__all__ = [
    "kbuild_trace",
    "dotconfig",
]
