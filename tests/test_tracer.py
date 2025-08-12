from pathlib import Path
from kcfgvex.kernel.kbuild_trace import Tracer


def make_simple_kernel_tree(root: Path):
    """Very small tree: single Makefile with one obj-$(CONFIG) rule."""
    src_dir = root / "drivers" / "net" / "ethernet" / "foo"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "bar.c").write_text("/* dummy */\n")
    (src_dir / "Makefile").write_text("obj-$(CONFIG_FOO_NET) += bar.o\n")
    return src_dir


def make_complex_kernel_tree(root: Path):
    """Create a more complex container + chain situation.

    Makefile contents:
        obj-$(CONFIG_TOP) += core.o     # CONFIG_TOP gates core.o
        core-objs += mid.o              # core.o contains mid.o
        mid-objs += leaf.o              # mid.o contains leaf.o
        mid-$(CONFIG_EXTRA) += extra.o  # mid.o conditionally contains extra.o via CONFIG_EXTRA

    Expected tracing:
        leaf.c  -> CONFIG_TOP
        extra.c -> CONFIG_TOP + CONFIG_EXTRA
    """
    src_dir = root / "drivers" / "complex"
    src_dir.mkdir(parents=True, exist_ok=True)
    for fname in ["leaf.c", "extra.c"]:
        (src_dir / fname).write_text("/* dummy */\n")
    (src_dir / "mid.c").write_text("/* mid */\n")
    (src_dir / "core.c").write_text("/* core */\n")
    (src_dir / "Makefile").write_text(
        "\n".join(
            [
                "obj-$(CONFIG_TOP) += core.o",
                "core-objs += mid.o",
                "mid-objs += leaf.o",
                "mid-$(CONFIG_EXTRA) += extra.o",
            ]
        )
        + "\n"
    )
    return src_dir


def test_tracer_simple_symbol(tmp_path: Path):
    tree = make_simple_kernel_tree(tmp_path)
    rel_file = str(tree.relative_to(tmp_path) / "bar.c")

    tracer = Tracer(tmp_path)
    res = tracer.trace(rel_file)
    assert "CONFIG_FOO_NET" in res.symbols

    tracer_filtered = Tracer(tmp_path, enabled_symbols={"CONFIG_OTHER"})
    res2 = tracer_filtered.trace(rel_file)
    assert "CONFIG_FOO_NET" not in res2.symbols

    tracer_filtered2 = Tracer(tmp_path, enabled_symbols={"CONFIG_FOO_NET"})
    res3 = tracer_filtered2.trace(rel_file)
    assert "CONFIG_FOO_NET" in res3.symbols


def test_tracer_container_chain(tmp_path: Path):
    tree = make_complex_kernel_tree(tmp_path)
    leaf_rel = str(tree.relative_to(tmp_path) / "leaf.c")
    extra_rel = str(tree.relative_to(tmp_path) / "extra.c")

    tracer = Tracer(tmp_path)
    leaf_res = tracer.trace(leaf_rel)
    assert leaf_res.symbols == {"CONFIG_TOP"}

    extra_res = tracer.trace(extra_rel)
    # Order doesn't matter; ensure both symbols recovered
    assert {"CONFIG_TOP", "CONFIG_EXTRA"} == extra_res.symbols

    # Filtering should drop symbols not enabled
    tracer_filtered = Tracer(tmp_path, enabled_symbols={"CONFIG_TOP"})
    leaf_res_f = tracer_filtered.trace(leaf_rel)
    assert leaf_res_f.symbols == {"CONFIG_TOP"}
    extra_res_f = tracer_filtered.trace(extra_rel)
    assert extra_res_f.symbols == {"CONFIG_TOP"}  # CONFIG_EXTRA filtered out

    tracer_filtered2 = Tracer(tmp_path, enabled_symbols={"CONFIG_EXTRA"})
    extra_res_only = tracer_filtered2.trace(extra_rel)
    # In this mode core chain still brings in CONFIG_EXTRA because it's directly gating extra.o
    assert extra_res_only.symbols == {"CONFIG_EXTRA"}
