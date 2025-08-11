use clap::{Parser, Subcommand};

use crate::cli::{
    cve_fetch::{cve_fetch_command, CveFetchArgs},
    trace::{trace_command, TraceArgs},
    yocto_scan::{yocto_scan_command, YoctoScanArgs},
};

pub mod cve_fetch;
pub mod trace;
pub mod yocto_scan;

#[derive(Parser)]
#[command(name = "kcfg-vex")]
#[command(about = "Kernel Config & VEX Utilities")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Trace(TraceArgs),
    CveFetch(CveFetchArgs),
    YoctoScan(YoctoScanArgs),
}
pub fn run_cli() -> crate::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Trace(trace_args) => trace_command(trace_args),
        Commands::CveFetch(cve_fetch_args) => cve_fetch_command(cve_fetch_args),
        Commands::YoctoScan(yocto_scan_args) => yocto_scan_command(yocto_scan_args),
    }
}
