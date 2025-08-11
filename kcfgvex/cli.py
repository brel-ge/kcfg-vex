import json
import typer
from pathlib import Path
from kcfgvex.kernel.kbuild_trace import Tracer
from kcfgvex.kernel.dotconfig import load_enabled
from kcfgvex.cve.fetch import fetch_many_cveorg, save_cve_json  # NEW
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
):
    """
    Load a Yocto cve_check JSON, select product 'linux_kernel', download all CVEs
    that are NOT 'Patched', and check which kernel configs enable the affected files.
    """
    if not yocto_json.exists():
        raise typer.BadParameter(f"Yocto JSON not found: {yocto_json}")
    if not linux_src.exists():
        raise typer.BadParameter(f"Linux source not found: {linux_src}")

    try:
        doc = json.loads(yocto_json.read_text())
    except Exception as e:
        raise typer.BadParameter(f"Failed to parse Yocto JSON: {e}")

    pkgs = doc.get("package", []) or []
    linux_pkgs = [
        p
        for p in pkgs
        if any(
            (isinstance(x, dict) and x.get("product") == "linux_kernel")
            for x in (p.get("products") or [])
        )
    ]
    if not linux_pkgs:
        typer.echo("No packages with product 'linux_kernel' found.", err=True)
        raise typer.Exit(0)

    cve_ids: list[str] = []
    for p in linux_pkgs:
        for it in p.get("issue") or []:
            if (it.get("status") or "").strip().lower() != "patched":
                cid = (it.get("id") or "").strip().upper()
                if cid.startswith("CVE-"):
                    cve_ids.append(cid)
    cve_ids = sorted(set(cve_ids))
    if not cve_ids:
        typer.echo("All linux_kernel issues are marked Patched. Nothing to do.")
        raise typer.Exit(0)

    enabled = load_enabled(dotconfig) if dotconfig else set()
    tracer = Tracer(linux_src, enabled_symbols=enabled)

    print(f"[bold]Found {len(cve_ids)} unpatched CVEs for linux_kernel[/bold]\n")

    # Use shared fetcher
    fetched = fetch_many_cveorg(
        cve_ids, show_progress=True, cache_dir=cache_dir, force=force_refresh
    )

    for cid in cve_ids:
        print(f"[bold cyan]{cid}[/bold cyan]")
        res = fetched.get(cid)
        if isinstance(res, Exception):
            print(f"  [red]Fetch failed:[/red] {res}\n")
            continue
        cve = res

        files = []
        cna = cve.get("containers", {}).get("cna", {})
        for aff in cna.get("affected", []) or []:
            files += aff.get("programFiles") or []
        files = sorted({f.lstrip("./") for f in files if isinstance(f, str)})

        if not files:
            print("  programFiles: - (not provided by CVE record)\n")
            continue

        all_syms = set()
        for f in files:
            tr = tracer.trace(f)
            syms = (
                tr.symbols if not enabled else {s for s in tr.symbols if s in enabled}
            )
            print(f"  - {f}")
            print(f"    objects: {', '.join(sorted(tr.objects)) or '-'}")
            print(f"    symbols: {', '.join(sorted(syms)) or '-'}")
            if show_graph:
                for e in tr.edges:
                    print(f"      [{e.via}] {e.src} -> {e.dst}")
            all_syms |= syms

        if all_syms:
            print("  union:", ", ".join(sorted(all_syms)))
        print()


def main():
    app()


if __name__ == "__main__":
    main()
