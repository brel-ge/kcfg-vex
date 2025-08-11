# kcfg-vex

Kernel Config & VEX Utilities – a small toolbox to:

1. Fetch CVE JSON records from CVE.org (CVE Services API).
2. Scan Yocto `cve_check` output for linux kernel CVEs that are not Patched and analyze which kernel configuration symbols enable the affected files.
3. Trace (simple static mapping) from kernel source file paths to object files and config symbols (via kbuild tracing) and optionally display reasoning edges.

## Features

- Rich progress bars while downloading multiple CVEs.
- Local on-disk caching of CVE JSONs to avoid refetching.
- `yocto-scan` convenience command: harvests unpatched linux kernel CVEs from a Yocto summary JSON and performs per-file symbol tracing.
- Direct `cve-fetch` command to grab one or many arbitrary CVEs.
- Optional filtering of reported symbols by an existing `.config` (only show enabled ones).

---

## Installation

Requirements: Python 3.12+.

Using [uv](https://github.com/astral-sh/uv) (recommended):

```bash
uv sync
```

Using pip / virtualenv:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

After install you get the console script:

```bash
kcfgvex --help
```

---

## Commands

### 1. Trace a single CVE JSON against kernel source

Given a downloaded CVE record (with `containers.cna.affected[].programFiles` populated):

```bash
kcfgvex trace cves/CVE-2025-21650.json /path/to/linux-src --dotconfig /path/to/.config --show-graph
```

Output shows for each file: object files, contributing symbols, and (when `--show-graph`) reasoning edges collected by the tracer. The final union of symbols is printed.

### 2. Fetch CVEs explicitly

```bash
kcfgvex cve-fetch CVE-2025-21649 CVE-2025-21650 --cache-dir cves
```

Options:
  
- `--cache-dir DIR` : Reuse/save `<CVE>.json` files (skips network when already present).
- `--force-refresh` : Redownload even if cached.
- `--quiet` : Suppress per-item messages & progress bar.

### 3. Yocto scan workflow

Point at a Yocto `cve_check` summary JSON (the variant that contains `package` entries & `issue` status fields) and your kernel source:

```bash
kcfgvex yocto-scan build/tmp/log/cve/cve-summary.json /path/to/linux-src \\
 --dotconfig /path/to/.config \\
 --cache-dir cves
```

It will:

1. Filter packages whose `products[].product == "linux_kernel"`.
2. Collect `issue[].id` where `status != 'Patched'`.
3. Fetch each CVE (using cache if provided).
4. For each CVE, trace `programFiles` into objects & symbols, applying `.config` filtering if supplied.

Progress bar only covers network fetches that were not already cached.

## CVE Caching Details

Caching is filename based (e.g. `cves/CVE-2025-21650.json`). A cached file is accepted when:

- It is valid JSON.
- Either no `cveMetadata.cveId` field is present or it matches the filename.

Use `--force-refresh` to ignore existing files. Newly fetched CVEs are always saved into the cache directory if provided.

---

## Debugging in VS Code

A debug configuration (`.vscode/launch.json`) includes an entry:

> kcfgvex yocto-scan

This launches the module `kcfgvex.cli` with the sample args. Adjust `args` or add variants (e.g. to pass `--dotconfig`). Ensure the interpreter is set to `.venv/bin/python` so dependencies resolve.

---

## Development

Run lint / formatting (example using ruff if you add it) and tests (none yet):

```bash
source .venv/bin/activate
python -m kcfgvex.cli --help
```
