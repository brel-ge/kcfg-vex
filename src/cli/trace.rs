use crate::kernel::tracer::{extract_program_files_from_cve, trace_kernel_config};
use camino::Utf8PathBuf;
use clap::Args;
use tracing::{info, warn};

#[derive(Args)]
pub struct TraceArgs {
    /// CVE JSON file path
    cve: Utf8PathBuf,
    /// Linux kernel source directory
    linux_src: Utf8PathBuf,
}

pub fn trace_command(args: TraceArgs) -> crate::Result<()> {
    info!("Tracing CVE: {}", args.cve);
    info!("Linux source: {}", args.linux_src);

    // Load CVE file and extract file paths to trace
    let cve_content = std::fs::read_to_string(&args.cve)?;
    let cve_data: serde_json::Value = serde_json::from_str(&cve_content)?;

    // Extract file paths from CVE data or use test file
    let files_to_trace = extract_program_files_from_cve(&cve_data);
    let mut all_symbols = std::collections::HashSet::new();
    let mut all_objects = std::collections::HashSet::new();
    let mut all_edges = Vec::new();

    for file_path in &files_to_trace {
        info!("Tracing file: {}", file_path);
        let result = trace_kernel_config(file_path, &args.linux_src)?;

        if let Some(error) = &result.error {
            warn!("Error tracing {}: {}", file_path, error);
            continue;
        }

        let symbols_count = result.symbols.len();
        let objects_count = result.objects.len();

        all_symbols.extend(result.symbols);
        all_objects.extend(result.objects);
        all_edges.extend(result.edges);

        info!(
            "Found {} symbols, {} objects for {}",
            symbols_count, objects_count, file_path
        );
    }

    info!(
        "Total trace results: {} symbols, {} objects",
        all_symbols.len(),
        all_objects.len()
    );

    // Print summary
    println!("CONFIG symbols found:");
    let mut sorted_symbols: Vec<_> = all_symbols.iter().collect();
    sorted_symbols.sort();
    for symbol in sorted_symbols {
        println!("  {}", symbol);
    }

    Ok(())
}
