import json
from kcfgvex import cli


def test_yocto_scan_generates_vex(tmp_path, monkeypatch):
    # Create minimal Linux tree and Makefile enabling foo.c via CONFIG_TESTSYM
    src_dir = tmp_path / "linux"
    file_dir = src_dir / "drivers" / "test"
    file_dir.mkdir(parents=True)
    (file_dir / "foo.c").write_text("/* test */\n")
    (file_dir / "Makefile").write_text("obj-$(CONFIG_TESTSYM) += foo.o\n")

    # .config enabling CONFIG_TESTSYM
    cfg_path = tmp_path / ".config"
    cfg_path.write_text("CONFIG_TESTSYM=y\n")

    # Yocto JSON referencing CVE-2025-1234 unpatched
    yocto_json = tmp_path / "yocto.json"
    yocto_doc = {
        "package": [
            {
                "products": [{"product": "linux_kernel"}],
                "issue": [
                    {"id": "CVE-2025-1234", "status": "Unpatched"},
                ],
            }
        ]
    }
    yocto_json.write_text(json.dumps(yocto_doc))

    # SBOM with kernel component
    sbom_path = tmp_path / "sbom.json"
    sbom_doc = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "linux-kernel", "bom-ref": "kernel"},
        ],
    }
    sbom_path.write_text(json.dumps(sbom_doc))

    # Monkeypatch fetch_many_cveorg to return programFiles
    def fake_fetch(ids, show_progress, cache_dir, force):  # signature match
        return {
            "CVE-2025-1234": {
                "containers": {
                    "cna": {
                        "affected": [
                            {"programFiles": ["drivers/test/foo.c"]}
                        ]
                    }
                }
            }
        }

    monkeypatch.setattr(cli, "fetch_many_cveorg", fake_fetch)

    vex_out = tmp_path / "out.vex.json"

    # Run function directly
    cli.yocto_scan(
        yocto_json=yocto_json,
        linux_src=src_dir,
        dotconfig=cfg_path,
        show_graph=False,
        cache_dir=None,
        force_refresh=False,
        sbom=sbom_path,
        vex_out=vex_out,
    )

    assert vex_out.exists()
    vex_doc = json.loads(vex_out.read_text())
    # Basic assertions
    flat = json.dumps(vex_doc)
    assert "CVE-2025-1234" in flat
    assert "affected" in flat
