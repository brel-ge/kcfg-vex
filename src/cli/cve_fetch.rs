use crate::cve::CveFetcher;
use camino::Utf8PathBuf;
use clap::Args;
use tracing::{error, info};

#[derive(Args)]
pub struct CveFetchArgs {
    /// CVE IDs to fetch
    cve: Vec<String>,
    /// Output directory for CVE files
    #[arg(long, default_value = "cves")]
    outdir: Utf8PathBuf,
    /// Suppress progress output
    #[arg(long)]
    quiet: bool,
    /// Cache directory for CVE data
    #[arg(long)]
    cache_dir: Option<Utf8PathBuf>,
    /// Force refresh cached CVE data
    #[arg(long)]
    force_refresh: bool,
}

pub fn cve_fetch_command(args: CveFetchArgs) -> crate::Result<()> {
    info!("Fetching {} CVEs", args.cve.len());

    let fetcher = CveFetcher::new();
    let cache_path = args.cache_dir.as_deref();

    let results = fetcher.fetch_many_cves(
        &args.cve,
        !args.quiet, // show_progress
        cache_path,
        args.force_refresh,
    );

    // Save results to output directory
    std::fs::create_dir_all(&args.outdir)?;

    for (cve_id, result) in results {
        match result {
            Ok(data) => {
                let output_file = args.outdir.join(format!("{}.json", cve_id));
                let content = serde_json::to_string_pretty(&data)?;
                std::fs::write(output_file, content)?;
                if !args.quiet {
                    info!("Saved {}", cve_id);
                }
            }
            Err(e) => {
                error!("Failed to fetch {}: {}", cve_id, e);
            }
        }
    }

    Ok(())
}
