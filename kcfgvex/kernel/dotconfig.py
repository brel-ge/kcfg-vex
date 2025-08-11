# kcfgvex/kernel/dotconfig.py
from __future__ import annotations

import gzip
import io
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, Tuple


__all__ = [
    "DotConfig",
    "load_enabled",
    "auto_find_config",
]


_TRISTATE_VALUES = {"y", "m", "n"}
_RE_ASSIGN = re.compile(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$")
_RE_NOT_SET = re.compile(r"^#\s*(CONFIG_[A-Za-z0-9_]+)\s+is not set\s*$")


@dataclass(frozen=True)
class DotConfig:
    """
    Parsed Linux kernel .config.

    Attributes
    ----------
    values : Dict[str, str]
        Map of symbol -> value.
        - tristate: "y" | "m" | "n"
        - string:   quoted (e.g., "\"/path\"") — you can strip quotes if you want
        - int/hex:  as-is (e.g., "1", "0xFF")
    """

    values: Dict[str, str]

    # ----------------------- Construction ---------------------------------

    @staticmethod
    def from_path(path: os.PathLike | str) -> "DotConfig":
        """Load and parse a .config from a file path (supports .gz)."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(p)
        data = _read_text_maybe_gz(p)
        return DotConfig.from_text(data)

    @staticmethod
    def from_text(text: str) -> "DotConfig":
        """Parse .config text."""
        vals: Dict[str, str] = {}
        for key, val in _iter_assignments(text.splitlines()):
            vals[key] = val
        return DotConfig(vals)

    # ----------------------- Queries --------------------------------------

    def get(self, symbol: str, default: str | None = None) -> str | None:
        """Return raw value or default if missing."""
        return self.values.get(symbol, default)

    def tristate(self, symbol: str) -> str | None:
        """
        Return "y" | "m" | "n" or None if symbol not present/doesn't parse as tristate.
        Missing symbols are effectively "n" in Kconfig, but we return None to distinguish.
        """
        v = self.values.get(symbol)
        if v in _TRISTATE_VALUES:
            return v
        # treat '# CONFIG_FOO is not set' as 'n' — encoded during parsing
        return None

    def is_enabled(self, symbol: str, include_modules: bool = True) -> bool:
        """
        True if symbol is enabled as built-in (=y) or (optionally) module (=m).
        """
        v = self.values.get(symbol)
        if v == "y":
            return True
        if include_modules and v == "m":
            return True
        return False

    def is_builtin(self, symbol: str) -> bool:
        """True if CONFIG_FOO=y."""
        return self.values.get(symbol) == "y"

    def is_module(self, symbol: str) -> bool:
        """True if CONFIG_FOO=m."""
        return self.values.get(symbol) == "m"

    def enabled_set(self, include_modules: bool = True) -> set[str]:
        """
        Return a set of CONFIG_* that are =y (and =m if include_modules=True).
        """
        keep = {"y", "m"} if include_modules else {"y"}
        return {k for k, v in self.values.items() if v in keep}

    # ----------------------- Utilities ------------------------------------

    def as_dict(self) -> Dict[str, str]:
        """Shallow copy of the underlying mapping."""
        return dict(self.values)

    def merge(self, other: "DotConfig") -> "DotConfig":
        """
        Return a new DotConfig with values from `other` overriding this one.
        Useful if you layer defaults + overrides.
        """
        merged = dict(self.values)
        merged.update(other.values)
        return DotConfig(merged)


# --------------------- Top-level convenience funcs -------------------------


def load_enabled(path: os.PathLike | str, include_modules: bool = True) -> set[str]:
    """
    Load a .config and return the set of enabled symbols (y and, optionally, m).
    """
    return DotConfig.from_path(path).enabled_set(include_modules=include_modules)


def auto_find_config(
    linux_src: os.PathLike | str | None = None,
    prefer_runtime: bool = True,
) -> Path | None:
    """
    Try to locate a kernel .config in common places:

      1) /proc/config.gz (running kernel)                 [if prefer_runtime]
      2) /boot/config-$(uname -r)                         [if prefer_runtime]
      3) <linux_src>/.config                              [if linux_src given]
      4) <linux_src>/usr/.config                          [some build layouts]

    Returns a Path if found, else None.
    """
    candidates: list[Path] = []

    if prefer_runtime:
        candidates.extend([Path("/proc/config.gz"), _boot_config_for_running_kernel()])

    if linux_src:
        root = Path(linux_src)
        candidates.extend([root / ".config", root / "usr" / ".config"])

    for p in candidates:
        if p and p.exists():
            return p
    return None


# --------------------------- Internal helpers ------------------------------


def _iter_assignments(lines: Iterable[str]) -> Iterator[Tuple[str, str]]:
    """
    Iterate over (CONFIG_FOO, value) pairs.

    Accepts:
      - CONFIG_FOO=y/m/n
      - CONFIG_BAR="string"
      - # CONFIG_BAZ is not set   -> yields ("CONFIG_BAZ", "n")

    Ignores comments and empty lines.
    """
    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        # '# CONFIG_X is not set'
        m = _RE_NOT_SET.match(line)
        if m:
            yield m.group(1), "n"
            continue

        # 'CONFIG_X=...'
        m = _RE_ASSIGN.match(line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            # Normalize some common values (leave others as-is)
            if val in _TRISTATE_VALUES:
                yield key, val
            else:
                # preserve quoted strings/numbers; callers can strip quotes if desired
                yield key, val
            continue

        # everything else ignored


def _read_text_maybe_gz(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rb") as f:
            return f.read().decode("utf-8", errors="ignore")
    return path.read_text(encoding="utf-8", errors="ignore")


def _boot_config_for_running_kernel() -> Path | None:
    try:
        import platform

        rel = platform.uname().release
        p = Path("/boot") / f"config-{rel}"
        return p if p.exists() else None
    except Exception:
        return None
