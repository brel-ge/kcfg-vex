# kcfg-vex

This tool provides kernel configuration dependency tracing and CycloneDX VEX (Vulnerability Exploitability eXchange) document generation.

## Features

- **CVE Fetching**: Download CVE data from CVE.org
- **Kernel Tracing**: Analyze Linux kernel configuration dependencies
- **VEX Generation**: Create CycloneDX VEX documents for vulnerability analysis
- **Yocto Integration**: Process Yocto CVE summaries

## Installation

### From Source

```bash
git clone https://github.com/brel-ge/kcfg-vex
cd kcfg-vex/kcfg-vex-rs
cargo build --release
```

The binary will be available at `target/release/kcfg-vex`.

## Usage

### Fetch CVE Data

```bash
# Fetch specific CVEs
kcfg-vex cve-fetch CVE-2023-1234 CVE-2023-5678

# Fetch with custom cache directory
kcfg-vex cve-fetch CVE-2023-1234 --cache-dir /path/to/cache

# Force refresh cached data
kcfg-vex cve-fetch CVE-2023-1234 --force-refresh
```

### Trace Kernel Dependencies

```bash
# Trace CVE impact on kernel configuration
kcfg-vex trace /path/to/cve.json /path/to/linux-src --dotconfig /path/to/.config

# Show dependency graph
kcfg-vex trace /path/to/cve.json /path/to/linux-src --show-graph
```

### Yocto CVE Scanning

```bash
# Scan Yocto CVE summary and generate VEX
kcfg-vex yocto-scan \
    /path/to/cve-summary.json \
    /path/to/linux-src \
    --dotconfig /path/to/.config \
    --sbom /path/to/sbom.json \
    --vex-out /path/to/output.vex.json
```

## Development

### Building

```bash
just
```

### Running Tests

```bash
just test
```
