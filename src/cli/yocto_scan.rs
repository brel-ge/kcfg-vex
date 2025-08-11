use crate::{
    cve::{derive_vex_state, write_split_vex_output, CveFetcher, VexEntry},
    kernel::{
        tracer::{extract_program_files_from_cve, trace_kernel_config},
        DotConfig,
    },
};
use camino::Utf8PathBuf;
use clap::Args;
use rayon::prelude::*;
use std::time::Instant;
use tracing::{info, warn};

#[derive(Args)]
pub struct YoctoScanArgs {
    /// Yocto CVE summary JSON file
    yocto_json: Utf8PathBuf,
    /// Linux kernel source directory
    linux_src: Utf8PathBuf,
    /// Kernel .config file path
    #[arg(long)]
    dotconfig: Option<Utf8PathBuf>,
    /// Cache directory for CVE data
    #[arg(long, default_value = "cves")]
    cache_dir: Utf8PathBuf,
    /// Force refresh cached CVE data
    #[arg(long)]
    force_refresh: bool,
    /// SBOM file path for component references
    #[arg(long)]
    sbom: Option<Utf8PathBuf>,
    /// VEX output file path
    #[arg(long)]
    vex_out: Option<Utf8PathBuf>,
    /// Config output file path for CVE-CONFIG pairs
    #[arg(long)]
    config_out: Option<Utf8PathBuf>,
    /// Only use cached CVE data, don't fetch new
    #[arg(long)]
    cache_only: bool,
}

pub fn yocto_scan_command(args: YoctoScanArgs) -> crate::Result<()> {
    info!("Scanning Yocto CVE summary: {}", args.yocto_json);

    // Load Yocto CVE summary
    let yocto_content = std::fs::read_to_string(&args.yocto_json)?;
    let yocto_data: serde_json::Value = serde_json::from_str(&yocto_content)?;

    // Extract CVE IDs from Yocto summary
    let cve_ids = extract_cve_ids_from_yocto(&yocto_data)?;
    info!(
        "Found {} CVEs in Yocto summary",
        cve_ids.remaining_cves.len()
    );
    info!(
        "Found {} patched CVEs in Yocto summary",
        cve_ids.patched_cves.len()
    );

    dbg!(cve_ids.patched_cves);

    // Load dotconfig if provided
    let enabled_symbols = if let Some(config_path) = args.dotconfig {
        info!("Loading kernel config: {}", config_path);
        let config = DotConfig::from_path(&config_path)?;
        Some(config.enabled_set(true)) // Include modules
    } else {
        None
    };

    // Fetch CVE data
    let fetcher = CveFetcher::new();
    let results = if args.cache_only {
        // Only load from cache
        let mut results = std::collections::HashMap::new();
        for cve_id in &cve_ids.remaining_cves {
            // Try to load from cache
            // TODO: Implement cache-only loading
            results.insert(
                cve_id.clone(),
                Err(crate::error::KcfgVexError::CveNotFound(cve_id.clone())),
            );
        }
        results
    } else {
        fetcher.fetch_many_cves(
            &cve_ids.remaining_cves,
            true, // show_progress
            Some(&args.cache_dir),
            args.force_refresh,
        )
    };

    // Load SBOM component refs if provided
    let sbom_component_refs = if let Some(sbom_path) = args.sbom {
        load_sbom_component_refs(&sbom_path)?
    } else {
        vec![]
    };

    // Process CVEs and collect results
    let mut vex_entries = Vec::new();
    let mut cve_config_pairs = Vec::new();
    let start_time = Instant::now();

    // Process CVEs in parallel
    let results: Result<Vec<_>, _> = cve_ids
        .remaining_cves
        .par_iter()
        .map(|cve_id| {
            info!("Processing CVE: {}", cve_id);
            process_single_cve_with_configs(
                &args.linux_src,
                cve_id,
                &results,
                &sbom_component_refs,
                &enabled_symbols,
            )
        })
        .collect();

    match results {
        Ok(processed_entries) => {
            for (i, (entry_opt, configs)) in processed_entries.into_iter().enumerate() {
                if let Some(entry) = entry_opt {
                    vex_entries.push(entry);
                }
                // Collect CVE-config pairs for TXT output
                let cve_id = &cve_ids.remaining_cves[i];
                for config in configs {
                    cve_config_pairs.push((cve_id.clone(), config));
                }
            }
        }
        Err(e) => return Err(e),
    }
    info!(
        "Processing took {:.2} seconds",
        start_time.elapsed().as_secs_f64()
    );

    if let Some(vex_path) = args.vex_out {
        info!("Generating split VEX output: {}", vex_path);
        write_split_vex_output(vex_entries, &vex_path)?;
    }

    // Write CVE-config pairs to TXT file if requested
    if let Some(config_path) = args.config_out {
        write_config_output(&cve_config_pairs, &config_path)?;
    }

    Ok(())
}

#[derive(Debug)]
struct ExtractedCves {
    remaining_cves: Vec<String>,
    patched_cves: Vec<String>,
}

fn extract_cve_ids_from_yocto(yocto_data: &serde_json::Value) -> crate::Result<ExtractedCves> {
    let mut cve_ids = std::collections::HashSet::new();
    let mut patched_cve_ids = std::collections::HashSet::new();

    // Parse Yocto CVE summary format: {"package": [...]}
    if let Some(packages) = yocto_data.get("package") {
        if let Some(packages_array) = packages.as_array() {
            for package in packages_array {
                // Check if this package has linux_kernel product
                let mut has_linux_kernel = false;
                if let Some(products) = package.get("products") {
                    if let Some(products_array) = products.as_array() {
                        for product in products_array {
                            if let Some(product_name) =
                                product.get("product").and_then(|v| v.as_str())
                            {
                                if product_name == "linux_kernel" {
                                    has_linux_kernel = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                // If package has linux_kernel product, extract CVEs
                if has_linux_kernel {
                    if let Some(issues) = package.get("issue") {
                        if let Some(issues_array) = issues.as_array() {
                            for issue in issues_array {
                                if let Some(cve_id) = issue.get("id").and_then(|v| v.as_str()) {
                                    if cve_id.starts_with("CVE-") {
                                        // Filter out issues with "Patched" status
                                        if let Some(status) =
                                            issue.get("status").and_then(|v| v.as_str())
                                        {
                                            if status == "Patched" {
                                                patched_cve_ids.insert(cve_id.to_string());
                                                continue; // Skip patched CVEs
                                            }
                                        }
                                        cve_ids.insert(cve_id.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Convert HashSet to Vec to deduplicate CVE IDs across packages
    Ok(ExtractedCves {
        remaining_cves: cve_ids.into_iter().collect(),
        patched_cves: patched_cve_ids.into_iter().collect(),
    })
}

fn load_sbom_component_refs(sbom_path: &camino::Utf8Path) -> crate::Result<Vec<String>> {
    let sbom_content = std::fs::read_to_string(sbom_path)?;
    let sbom_doc: serde_json::Value = serde_json::from_str(&sbom_content)?;

    if sbom_doc.get("bomFormat").and_then(|v| v.as_str()) != Some("CycloneDX") {
        return Err(crate::error::KcfgVexError::InvalidConfig(
            "SBOM is not CycloneDX JSON".to_string(),
        ));
    }

    let serial_raw = sbom_doc
        .get("serialNumber")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let serial_uuid = if serial_raw.is_empty() {
        "unknown".to_string()
    } else {
        serial_raw
            .split(':')
            .next_back()
            .unwrap_or("unknown")
            .to_string()
    };
    let bom_version = sbom_doc
        .get("version")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    let mut out_refs = Vec::new();
    if let Some(components) = sbom_doc.get("components").and_then(|v| v.as_array()) {
        for comp in components {
            if comp.get("name").and_then(|v| v.as_str()) == Some("linux_kernel") {
                let bref = comp
                    .get("bom-ref")
                    .or_else(|| comp.get("bomRef"))
                    .or_else(|| comp.get("purl"))
                    .or_else(|| comp.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("kernel");

                out_refs.push(format!("urn:cdx:{}/{}#{}", serial_uuid, bom_version, bref));
            }
        }
    }

    if out_refs.is_empty() {
        warn!("No linux_kernel component in SBOM; using synthetic BOM-Link ref");
        out_refs.push(format!("urn:cdx:{}/{}#kernel", serial_uuid, bom_version));
    }

    Ok(out_refs)
}

fn process_single_cve_with_configs(
    src_root: &Utf8PathBuf,
    cve_id: &str,
    results: &std::collections::HashMap<
        String,
        Result<serde_json::Value, crate::error::KcfgVexError>,
    >,
    sbom_component_refs: &[String],
    enabled_symbols: &Option<std::collections::HashSet<String>>,
) -> crate::Result<(Option<VexEntry>, std::collections::HashSet<String>)> {
    info!("Processing CVE: {}", cve_id);

    let cve_result = results.get(cve_id);
    match cve_result {
        Some(Ok(cve_data)) => {
            let files = extract_program_files_from_cve(cve_data);
            if files.is_empty() {
                info!("  No programFiles found in CVE record");
                if !sbom_component_refs.is_empty() {
                    return Ok((
                        Some(VexEntry::new(
                            cve_id.to_string(),
                            "under_investigation".to_string(),
                            "No programFiles in CVE record".to_string(),
                            None,
                            sbom_component_refs.to_vec(),
                        )),
                        std::collections::HashSet::new(),
                    ));
                }
                return Ok((None, std::collections::HashSet::new()));
            }

            let mut union_symbols = std::collections::HashSet::new();
            info!("  Found {} program files to trace", files.len());

            for file_path in &files {
                info!("    Tracing: {}", file_path);
                let trace_result = trace_kernel_config(file_path, src_root)?;

                if let Some(error) = &trace_result.error {
                    warn!("      Error tracing {}: {}", file_path, error);
                    continue;
                }

                info!("      Objects: {}", trace_result.objects.len());
                info!("      Symbols: {}", trace_result.symbols.len());
                union_symbols.extend(trace_result.symbols);
            }

            let is_enabled = if let Some(enabled) = enabled_symbols {
                !union_symbols
                    .intersection(enabled)
                    .collect::<Vec<_>>()
                    .is_empty()
            } else {
                false
            };

            info!("  Union symbols: {:?}", union_symbols);
            info!("  Enabled: {}", is_enabled);

            let (state, justification, detail) = derive_vex_state(is_enabled, &union_symbols);

            if !sbom_component_refs.is_empty() {
                Ok((
                    Some(VexEntry::new(
                        cve_id.to_string(),
                        state,
                        detail,
                        justification,
                        sbom_component_refs.to_vec(),
                    )),
                    union_symbols,
                ))
            } else {
                Ok((None, union_symbols))
            }
        }
        Some(Err(e)) => {
            warn!("  Fetch failed: {}", e);
            Ok((None, std::collections::HashSet::new()))
        }
        None => {
            warn!("  CVE not found in results");
            Ok((None, std::collections::HashSet::new()))
        }
    }
}

fn write_config_output(
    cve_config_pairs: &[(String, String)],
    config_out: &camino::Utf8Path,
) -> crate::Result<()> {
    use std::fs;
    use std::io::Write;

    // Ensure parent directory exists
    if let Some(parent) = config_out.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = fs::File::create(config_out)?;

    // Sort pairs for consistent output
    let mut sorted_pairs = cve_config_pairs.to_vec();
    sorted_pairs.sort();

    for (cve_id, config) in sorted_pairs {
        writeln!(file, "{} {}", cve_id, config)?;
    }

    info!(
        "Wrote {} CVE-config pairs to {}",
        cve_config_pairs.len(),
        config_out
    );
    Ok(())
}
