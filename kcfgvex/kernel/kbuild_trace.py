from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from collections import deque
from typing import Iterable, Sequence, Tuple, Dict, Set, List
import re


__all__ = ["Tracer", "TraceResult", "TraceEdge"]


@dataclass(frozen=True)
class TraceEdge:
    """A reasoning edge explaining how we inferred a relationship."""

    src: str  # e.g., "hclge_ptp.o@drivers/.../hns3pf"
    dst: str  # e.g., "CONFIG:CONFIG_HNS3_HCLGE" or "hclge.o@drivers/.../hns3"
    via: str  # e.g., "obj-$(CONFIG) += target", "container includes target", "parent Makefile gate"


@dataclass(frozen=True)
class TraceResult:
    """Final result for a single file trace."""

    file: str  # input source path (relative to src_root)
    objects: Set[str]  # objects (including containers) involved
    symbols: Set[str]  # enabling CONFIG_* symbols inferred
    edges: List[TraceEdge]  # explanation graph
    error: str | None = None  # optional error string if file was missing


class Tracer:
    """
    Trace which Kconfig symbols enable building a given Linux kernel source file.

    Heuristics covered:
      - obj-$(CONFIG_FOO) += <target>
      - <container>-(y|m|$(CONFIG_BAR)) += <target>
      - <container>-objs :=/+= <target>
      - <container>-objs-$(CONFIG_BAZ) :=/+= <target>
      - parent Makefiles referencing children as 'subdir/target'
      - directory gates: obj-$(CONFIG_QUX) += subdir/

    Parameters
    ----------
    src_root : Path | str
        Path to the Linux kernel source tree.
    enabled_symbols : Iterable[str] | None
        Optional set of CONFIG_* names (e.g., from .config with =y/=m). If provided,
        `trace()` will filter the discovered symbols to those present here.
    makefile_names : Sequence[str]
        Filenames considered as Kbuild "makefiles" per directory. Defaults to ("Makefile", "Kbuild").

    Usage
    -----
    >>> tracer = Tracer("/path/to/linux", enabled_symbols={"CONFIG_HNS3_HCLGE"})
    >>> res = tracer.trace("drivers/net/ethernet/hisilicon/hns3/hns3pf/hclge_ptp.c")
    >>> sorted(res.symbols)
    ['CONFIG_HNS3_HCLGE']
    """

    def __init__(
        self,
        src_root: Path | str,
        enabled_symbols: Iterable[str] | None = None,
        makefile_names: Sequence[str] = ("Makefile", "Kbuild"),
    ) -> None:
        self.src_root = Path(src_root).resolve()
        self.enabled_symbols = set(enabled_symbols or [])
        self.makefile_names = tuple(makefile_names)

        # Small cache to avoid re-reading Makefiles
        self._makefile_cache: Dict[Path, List[str]] = {}

    # --------------------------- Public API ---------------------------------

    def trace(self, rel_file: str) -> TraceResult:
        """
        Trace enabling CONFIG_* symbols for the provided source file path (relative to src_root).
        """
        rel = rel_file.strip().lstrip("./")
        src_path = self.src_root / rel

        if not src_path.exists():
            return TraceResult(
                file=rel_file,
                objects=set(),
                symbols=set(),
                edges=[],
                error=f"File not found in source tree: {src_path}",
            )

        obj_name = Path(rel).name.replace(".c", ".o")
        file_dir = src_path.parent

        symbols: Set[str] = set()
        objects: Set[str] = {obj_name}
        edges: List[TraceEdge] = []

        # BFS queue over (directory, target-object)
        queue: deque[Tuple[Path, str]] = deque([(file_dir, obj_name)])
        visited: Set[Tuple[str, str]] = set()

        while queue:
            cur_dir, target = queue.popleft()
            key = (str(cur_dir), target)
            if key in visited:
                continue
            visited.add(key)

            # (A) Inspect current directory's Makefile/Kbuild
            for mf in self._iter_makefiles(cur_dir):
                res = _scan_makefile_for_targets(
                    mf, [target], subdir=None, read_lines=self._read_makefile_lines
                )

                for cfg in res["configs_for_target"]:
                    if self._keep_symbol(cfg):
                        symbols.add(cfg)
                        edges.append(
                            TraceEdge(
                                src=f"{target}@{cur_dir}",
                                dst=f"CONFIG:{cfg}",
                                via="obj-$(CONFIG) includes target",
                            )
                        )

                for container in res["containers"]:
                    if container not in objects:
                        objects.add(container)
                        edges.append(
                            TraceEdge(
                                src=f"{target}@{cur_dir}",
                                dst=f"{container}@{cur_dir}",
                                via="container includes target",
                            )
                        )
                        queue.append((cur_dir, container))

            # (B) Walk parent directories:
            # - Parent may reference this child object using a relative path (childdir/target)
            # - Parent may gate the child directory: obj-$(CONFIG) += <childdir>/
            scan_child = cur_dir
            parent = scan_child.parent
            while self._is_within(parent) and parent != parent.parent:
                # Build a representation of our target relative to the parent dir
                parent_rel_target = _object_path_relative_to(src_path, parent)
                targets_for_parent = [target, parent_rel_target]

                for mf in self._iter_makefiles(parent):
                    res_parent = _scan_makefile_for_targets(
                        mf,
                        targets_for_parent,
                        subdir=scan_child.name,
                        read_lines=self._read_makefile_lines,
                    )

                    for cfg in res_parent["configs_for_target"]:
                        if self._keep_symbol(cfg):
                            symbols.add(cfg)
                            edges.append(
                                TraceEdge(
                                    src=f"{target}@{scan_child}",
                                    dst=f"CONFIG:{cfg}",
                                    via="parent Makefile gate",
                                )
                            )

                    for container in res_parent["containers"]:
                        if container not in objects:
                            objects.add(container)
                            edges.append(
                                TraceEdge(
                                    src=f"{target}@{scan_child}",
                                    dst=f"{container}@{parent}",
                                    via="parent container includes target",
                                )
                            )
                            # Important: the container is defined in the parent dir
                            queue.append((parent, container))

                if parent == self.src_root:
                    break
                scan_child = parent
                parent = scan_child.parent

        return TraceResult(file=rel_file, objects=objects, symbols=symbols, edges=edges)

    # --------------------------- Internals ----------------------------------

    def _keep_symbol(self, cfg: str) -> bool:
        """Return True if the symbol passes (or we don't filter)."""
        if not self.enabled_symbols:
            return True
        return cfg in self.enabled_symbols

    def _iter_makefiles(self, directory: Path) -> Iterable[Path]:
        """Yield existing makefiles for the directory in order."""
        for name in self.makefile_names:
            p = directory / name
            if p.exists():
                yield p

    def _is_within(self, path: Path) -> bool:
        """True if `path` is equal to or inside `self.src_root`."""
        try:
            path.resolve().relative_to(self.src_root)
            return True
        except Exception:
            return False

    # File reading with caching
    def _read_makefile_lines(self, p: Path) -> List[str]:
        if p in self._makefile_cache:
            return self._makefile_cache[p]
        lines = _read_makefile_lines_no_cache(p)
        self._makefile_cache[p] = lines
        return lines


# ------------------------- Free helpers / regexes ---------------------------

# Compile once for speed
_RE_SPACE = re.compile(r"\s+")
# patterns are built dynamically per-target; container names reuse the same character class
_CONTAINER_NAME = r"[A-Za-z0-9_]+"


def _read_makefile_lines_no_cache(p: Path) -> List[str]:
    """Read Makefile/Kbuild, join backslash-continued lines, strip/compact whitespace."""
    if not p.exists():
        return []
    raw = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    joined: List[str] = []
    buf = ""
    for line in raw:
        s = line.rstrip()
        if s.endswith("\\"):
            buf += s[:-1] + " "
        else:
            buf += s
            joined.append(buf)
            buf = ""
    if buf:
        joined.append(buf)
    out: List[str] = []
    for l in joined:
        l = _RE_SPACE.sub(" ", l).strip()
        if l:
            out.append(l)
    return out


def _object_path_relative_to(src_path: Path, ancestor_dir: Path) -> str:
    """
    Return object path (with .o) relative to ancestor_dir, e.g. 'hns3pf/hclge_ptp.o'.
    Falls back to basename if relative() fails.
    """
    try:
        rel_to_parent = src_path.with_suffix(".o").relative_to(ancestor_dir)
        return rel_to_parent.as_posix()
    except Exception:
        return src_path.with_suffix(".o").name


def _scan_makefile_for_targets(
    make_path: Path,
    targets: Sequence[str],
    subdir: str | None,
    read_lines,
) -> Dict[str, Set[str]]:
    """
    Scan a single Makefile/Kbuild for relationships involving any of `targets`.

    Returns dict with keys:
      - "configs_for_target": set of CONFIG_* that directly/indirectly gate targets
      - "containers":         set of container object names (e.g., 'hclge.o') that include targets
      - "dir_configs":        set of CONFIG_* that gate `subdir/` (if subdir is provided)
    """
    lines = read_lines(make_path)
    configs_for_target: Set[str] = set()
    containers: Set[str] = set()
    dir_configs: Set[str] = set()

    if not targets:
        return {
            "configs_for_target": configs_for_target,
            "containers": containers,
            "dir_configs": dir_configs,
        }

    # Build a single OR pattern for multiple targets (object basenames and/or relative paths)
    tgt_pat = r"(?:%s)" % "|".join(re.escape(t) for t in targets)

    for line in lines:
        # 1) obj-$(CONFIG_FOO) += <target>
        m = re.search(rf"\bobj-\$\((CONFIG_[A-Z0-9_]+)\)\s*\+?=\s.*\b{tgt_pat}\b", line)
        if m:
            configs_for_target.add(m.group(1))

        # 2) <container>-(y|m|$(CONFIG_BAR)) += <target>
        m = re.search(
            rf"\b({_CONTAINER_NAME})-(y|m|\$\((CONFIG_[A-Z0-9_]+)\))\s*[:+]?=\s.*\b{tgt_pat}\b",
            line,
        )
        if m:
            containers.add(m.group(1) + ".o")
            if m.group(3):
                configs_for_target.add(m.group(3))

        # 3) <container>-objs :=/+= <target>
        m = re.search(rf"\b({_CONTAINER_NAME})-objs\s*[:+]?=\s.*\b{tgt_pat}\b", line)
        if m:
            containers.add(m.group(1) + ".o")

        # 4) <container>-objs-$(CONFIG_BAZ) :=/+= <target>
        m = re.search(
            rf"\b({_CONTAINER_NAME})-objs-\$\((CONFIG_[A-Z0-9_]+)\)\s*[:+]?=\s.*\b{tgt_pat}\b",
            line,
        )
        if m:
            containers.add(m.group(1) + ".o")
            configs_for_target.add(m.group(2))

        # 5) directory gating: obj-$(CONFIG_QUX) += subdir/
        if subdir:
            subdir_esc = re.escape(subdir.rstrip("/") + "/")
            m = re.search(
                rf"\bobj-\$\((CONFIG_[A-Z0-9_]+)\)\s*\[:+]?=\s.*\b{subdir_esc}\b", line
            )
            if m:
                dir_configs.add(m.group(1))
                # Note: dir gate alone doesn't identify the final object; it indicates higher-level control

    return {
        "configs_for_target": configs_for_target,
        "containers": containers,
        "dir_configs": dir_configs,
    }
