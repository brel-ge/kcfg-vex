import textwrap
from pathlib import Path
from kcfgvex.kernel.dotconfig import DotConfig, load_enabled

def test_dotconfig_parsing_basic(tmp_path: Path):
    raw = textwrap.dedent(
        """
        CONFIG_FOO=y
        CONFIG_BAR=m
        # CONFIG_BAZ is not set
        CONFIG_PATH="/tmp/foo"
        CONFIG_NUM=42
        """
    ).strip() + "\n"
    cfg = DotConfig.from_text(raw)
    assert cfg.tristate("CONFIG_FOO") == "y"
    assert cfg.is_enabled("CONFIG_BAR")
    assert cfg.tristate("CONFIG_BAZ") == "n" or cfg.get("CONFIG_BAZ") == "n"
    # enabled_set should include FOO and BAR, not BAZ
    enabled = cfg.enabled_set()
    assert "CONFIG_FOO" in enabled and "CONFIG_BAR" in enabled and "CONFIG_BAZ" not in enabled

    # write to file to test load_enabled
    p = tmp_path / ".config"
    p.write_text(raw)
    loaded_enabled = load_enabled(p)
    assert loaded_enabled == enabled


def test_dotconfig_merge():
    a = DotConfig.from_text("CONFIG_FOO=y\nCONFIG_BAR=m\n")
    b = DotConfig.from_text("CONFIG_BAR=y\nCONFIG_BAZ=m\n")
    merged = a.merge(b)
    assert merged.get("CONFIG_FOO") == "y"
    assert merged.get("CONFIG_BAR") == "y"  # overridden
    assert merged.get("CONFIG_BAZ") == "m"
