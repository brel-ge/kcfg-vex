import json
import typer
from pathlib import Path
from kcfgvex.kernel.kbuild_trace import Tracer
from kcfgvex.kernel.dotconfig import load_enabled
from kcfgvex.cve.fetch import fetch_many_cveorg, save_cve_json  # NEW
from kcfgvex.cve.vex import VEXEntry, build_vex, save_vex
from rich import print

app = typer.Typer(help="Kernel Config & VEX Utilities")


@app.command()
def trace(
    cve: Path, linux_src: Path, dotconfig: Path | None = None, show_graph: bool = False
):
    """
    Trace a given CVE JSON against the Linux kernel source to find
    the kernel config which activate the affected files.
    """
    data = json.loads(cve.read_text())
    files = []
    for aff in data.get("containers", {}).get("cna", {}).get("affected", []):
        files += aff.get("programFiles") or []
    files = sorted({f.lstrip("./") for f in files})
    if not files:
        typer.echo("No programFiles in CVE JSON", err=True)
        raise typer.Exit(2)

    tracer = Tracer(linux_src)
    enabled = load_enabled(dotconfig) if dotconfig else set()

    all_syms = set()
    for f in files:
        res = tracer.trace(f)
        syms = res.symbols
        if enabled:
            syms = {s for s in syms if s in enabled}
        print(f"[bold]- {f}[/bold]")
        print(f"  objects: {', '.join(sorted(res.objects)) or '-'}")
        print(f"  symbols: {', '.join(sorted(syms)) or '-'}")
        if show_graph:
            for e in res.edges:
                print(f"    [{e.via}] {e.src} -> {e.dst}")
        all_syms |= syms

    if all_syms:
        print("\n[bold]Union:[/bold]")
        for s in sorted(all_syms):
            print(f"- {s}")


@app.command("cve-fetch")
def cve_fetch(
    cve: list[str] = typer.Argument(
        ..., help="One or more CVE IDs (e.g., CVE-2025-21649)"
    ),
    outdir: Path = typer.Option(Path("cves"), "--outdir", help="Output directory"),
    quiet: bool = typer.Option(
        False, "--quiet/--no-quiet", help="Suppress per-item messages"
    ),
    cache_dir: Path | None = typer.Option(
        None,
        "--cache-dir",
        help="Directory to cache CVE JSONs (reuse if present)",
    ),
    force_refresh: bool = typer.Option(
        False,
        "--force-refresh/--no-force-refresh",
        help="Ignore cache and re-download all specified CVEs",
    ),
):
    """
    Download one or more CVEs from CVE.org and save them as JSON files.
    """
    results = fetch_many_cveorg(
        [x.upper() for x in cve],
        show_progress=not quiet,
        cache_dir=cache_dir,
        force=force_refresh,
    )
    outdir.mkdir(parents=True, exist_ok=True)

    ok = 0
    for cid, res in results.items():
        if isinstance(res, Exception):
            if not quiet:
                print(f"[red]{cid}[/red]: {res}")
            continue
        save_cve_json(res, outdir / f"{cid}.json")
        ok += 1
        if not quiet:
            print(f"[green]{cid}[/green] -> {outdir / f'{cid}.json'}")

    if not quiet:
        print(f"\nSaved {ok}/{len(results)} CVEs to {outdir}")


# ------------------------ UPDATED: yocto-scan uses fetch module -------------
@app.command("yocto-scan")
def yocto_scan(
    yocto_json: Path = typer.Argument(..., help="Path to Yocto cve_check JSON"),
    linux_src: Path = typer.Argument(..., help="Path to Linux kernel source"),
    dotconfig: Path | None = typer.Option(
        None, "--dotconfig", help="Path to .config to filter (=y/=m)"
    ),
    show_graph: bool = typer.Option(
        False, "--show-graph/--no-show-graph", help="Print reasoning edges"
    ),
    cache_dir: Path | None = typer.Option(
        Path("cves"),
        "--cache-dir",
        help="Directory to cache downloaded CVE JSON files (default: ./cves)",
    ),
    force_refresh: bool = typer.Option(
        False,
        "--force-refresh/--no-force-refresh",
        help="Ignore cache and re-download all CVEs",
    ),
    sbom: Path | None = typer.Option(
        None,
        "--sbom",
        help="CycloneDX SBOM JSON path to enable VEX generation (requires --vex-out)",
    ),
    vex_out: Path | None = typer.Option(
        None,
        "--vex-out",
        help="Write CycloneDX VEX JSON to this path (requires --sbom)",
    ),
):
    """
    Load a Yocto cve_check JSON, select product 'linux_kernel', download all CVEs
    that are NOT 'Patched', and check which kernel configs enable the affected files.
    """
    if not yocto_json.exists():
        raise typer.BadParameter(f"Yocto cve_check JSON not found: {yocto_json}")
    if not linux_src.exists():
        raise typer.BadParameter(f"Linux source not found: {linux_src}")

    doc = _load_json_or_die(yocto_json, "Yocto cve_check JSON")
    linux_pkgs = _select_linux_kernel_packages(doc)
    if not linux_pkgs:
        typer.echo("No packages with product 'linux_kernel' found.", err=True)
        raise typer.Exit(0)

    cve_ids = _collect_unpatched_cve_ids(linux_pkgs)
    if not cve_ids:
        typer.echo("All linux_kernel issues are marked Patched. Nothing to do.")
        raise typer.Exit(0)

    enabled = load_enabled(dotconfig) if dotconfig else set()
    tracer = Tracer(linux_src, enabled_symbols=enabled)
    raw_tracer = Tracer(linux_src)

    print(f"[bold]Found {len(cve_ids)} unpatched CVEs for linux_kernel[/bold]\n")

    fetched = fetch_many_cveorg(
        cve_ids, show_progress=True, cache_dir=cache_dir, force=force_refresh
    )

    if (vex_out and not sbom) or (sbom and not vex_out):
        raise typer.BadParameter("--sbom and --vex-out must be provided together")

    sbom_component_refs = _load_sbom_component_refs(sbom) if sbom else []
    vex_entries: list[VEXEntry] = []

    for cid in cve_ids:
        entry = _process_single_cve(
            cid=cid,
            fetched=fetched,
            tracer=tracer,
            raw_tracer=raw_tracer,
            show_graph=show_graph,
            sbom_component_refs=sbom_component_refs,
        )
        if entry is not None:
            vex_entries.append(entry)

    if vex_out and sbom_component_refs:
        _write_vex_output(vex_entries, vex_out)


# ---------------- Helper functions for yocto-scan -----------------
def _load_json_or_die(path: Path, label: str) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception as e:
        raise typer.BadParameter(f"Failed to parse {label}: {e}")


def _select_linux_kernel_packages(doc: dict) -> list[dict]:
    pkgs = doc.get("package", []) or []
    return [
        p
        for p in pkgs
        if any(
            (isinstance(x, dict) and x.get("product") == "linux_kernel")
            for x in (p.get("products") or [])
        )
    ]


def _collect_unpatched_cve_ids(linux_pkgs: list[dict]) -> list[str]:
    cve_ids: list[str] = []
    for p in linux_pkgs:
        for it in p.get("issue") or []:
            if (it.get("status") or "").strip().lower() != "patched":
                cid = (it.get("id") or "").strip().upper()
                if cid.startswith("CVE-"):
                    cve_ids.append(cid)
    return sorted(set(cve_ids))




def _load_sbom_component_refs(sbom: Path) -> list[str]:
    if not sbom.exists():
        raise typer.BadParameter(f"SBOM not found: {sbom}")
    sbom_doc = _load_json_or_die(sbom, "SBOM JSON")
    if sbom_doc.get("bomFormat") != "CycloneDX":
        raise typer.BadParameter("SBOM is not CycloneDX JSON")
    refs: list[str] = []
    for comp in sbom_doc.get("components") or []:
        name = (comp.get("name") or "").lower()
        purl = (comp.get("purl") or "").lower()
        if any(k in name for k in ["linux", "kernel"]) or any(
            k in purl for k in ["linux", "kernel"]
        ):
            bref = (
                comp.get("bom-ref")
                or comp.get("bomRef")
                or comp.get("purl")
                or comp.get("name")
            )
            if bref:
                refs.append(bref)
    if not refs:
        typer.echo(
            "Warning: no kernel-like component in SBOM; using synthetic 'kernel' ref",
            err=True,
        )
        refs.append("kernel")
    return refs


def _process_single_cve(
    cid: str,
    fetched: dict,
    tracer: Tracer,
    raw_tracer: Tracer,
    show_graph: bool,
    sbom_component_refs: list[str],
) -> VEXEntry | None:
    print(f"[bold cyan]{cid}[/bold cyan]")
    res = fetched.get(cid)
    if isinstance(res, Exception):
        print(f"  [red]Fetch failed:[/red] {res}\n")
        return None
    cve = res

    files = _extract_program_files(cve)
    if not files:
        print("  programFiles: - (not provided by CVE record)\n")
        if sbom_component_refs:
            return VEXEntry(
                cve_id=cid,
                state="under_investigation",
                justification=None,
                detail="No programFiles in CVE record",
                component_refs=sbom_component_refs,
            )
        return None

    union_filtered: set[str] = set()
    union_raw: set[str] = set()
    for f in files:
        tr_raw = raw_tracer.trace(f)
        tr_f = tracer.trace(f)
        raw_syms = tr_raw.symbols
        syms = tr_f.symbols
        print(f"  - {f}")
        print(f"    objects: {', '.join(sorted(tr_f.objects)) or '-'}")
        print(
            f"    symbols: {', '.join(sorted(syms)) or '-'} (raw: {', '.join(sorted(raw_syms)) or '-'})"
        )
        if show_graph:
            for e in tr_f.edges:
                print(f"      [{e.via}] {e.src} -> {e.dst}")
        union_filtered |= syms
        union_raw |= raw_syms

    if union_filtered:
        print("  union:", ", ".join(sorted(union_filtered)))
    print()

    state, justification, detail = _derive_vex_state(union_filtered, union_raw)
    if sbom_component_refs:
        return VEXEntry(
            cve_id=cid,
            state=state,
            justification=justification,
            detail=detail,
            component_refs=sbom_component_refs,
        )
    return None


def _extract_program_files(cve_record: dict) -> list[str]:
    files: list[str] = []
    cna = cve_record.get("containers", {}).get("cna", {})
    for aff in cna.get("affected", []) or []:
        files += aff.get("programFiles") or []
    return sorted({f.lstrip("./") for f in files if isinstance(f, str)})


def _derive_vex_state(union_filtered: set[str], union_raw: set[str]):
    if union_filtered:
        return (
            "affected",
            None,
            f"Enabled symbols: {', '.join(sorted(union_filtered))}",
        )
    if union_raw:
        return (
            "not_affected",
            "vulnerable_code_not_in_execute_path",
            "Required symbols present in source but not enabled in provided .config: "
            + ", ".join(sorted(union_raw)),
        )
    return (
        "under_investigation",
        None,
        "Could not infer enabling symbols for listed programFiles",
    )


def _write_vex_output(vex_entries: list[VEXEntry], vex_out: Path):
    vex_doc = build_vex(vex_entries)
    save_vex(vex_doc, vex_out)
    print(
        f"[green]Wrote VEX:[/green] {vex_out} ({len(vex_entries)} entries, {sum(1 for e in vex_entries if e.state == 'affected')} affected)"
    )


def main():
    app()


if __name__ == "__main__":
    main()
