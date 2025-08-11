use camino::Utf8Path;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexEntry {
    pub cve_id: String,
    pub state: String, // affected | not_affected | under_investigation
    pub justification: Option<String>,
    pub detail: String,
    pub component_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexSource {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexAnalysis {
    pub state: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexAffects {
    #[serde(rename = "ref")]
    pub component_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexVulnerability {
    pub id: String,
    pub source: VexSource,
    pub analysis: VexAnalysis,
    pub affects: Vec<VexAffects>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexMetadata {
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxVex {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    pub version: u32,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub metadata: VexMetadata,
    pub vulnerabilities: Vec<VexVulnerability>,
}

impl VexEntry {
    pub fn new(
        cve_id: String,
        state: String,
        detail: String,
        justification: Option<String>,
        component_refs: Vec<String>,
    ) -> Self {
        Self {
            cve_id,
            state,
            justification,
            detail,
            component_refs,
        }
    }
}

pub fn derive_vex_state(
    is_enabled: bool,
    union_symbols: &std::collections::HashSet<String>,
) -> (String, Option<String>, String) {
    if union_symbols.is_empty() {
        (
            "under_investigation".to_string(),
            None,
            "Could not infer enabling symbols for listed programFiles".to_string(),
        )
    } else if is_enabled {
        let symbols_list: Vec<_> = union_symbols.iter().cloned().collect();
        (
            "affected".to_string(),
            None,
            format!("Enabled symbols: {}", symbols_list.join(", ")),
        )
    } else {
        let symbols_list: Vec<_> = union_symbols.iter().cloned().collect();
        (
            "not_affected".to_string(),
            Some("code_not_reachable".to_string()),
            format!(
                "Required symbols present in source but not enabled in provided .config: {}",
                symbols_list.join(", ")
            ),
        )
    }
}

pub fn build_vex(
    entries: Vec<VexEntry>,
    spec_version: Option<String>,
    serial_number: Option<String>,
) -> CycloneDxVex {
    let vulnerabilities: Vec<VexVulnerability> = entries
        .into_iter()
        .map(|entry| {
            let mut analysis = VexAnalysis {
                state: entry.state.clone(),
                detail: entry.detail,
                justification: entry.justification.clone(),
            };

            // Add justification only for not_affected state
            if entry.state == "not_affected" {
                analysis.justification = entry.justification;
            }

            VexVulnerability {
                id: entry.cve_id.clone(),
                source: VexSource {
                    name: "NVD".to_string(),
                    url: format!("https://nvid.nist.gov/vuln/detail/{}", entry.cve_id),
                },
                analysis,
                affects: entry
                    .component_refs
                    .into_iter()
                    .map(|component_ref| VexAffects { component_ref })
                    .collect(),
            }
        })
        .collect();

    let serial = serial_number.unwrap_or_else(|| format!("urn:uuid:{}", Uuid::new_v4()));

    CycloneDxVex {
        bom_format: "CycloneDX".to_string(),
        spec_version: spec_version.unwrap_or_else(|| "1.4".to_string()),
        version: 1,
        serial_number: serial,
        metadata: VexMetadata {
            timestamp: Utc::now(),
        },
        vulnerabilities,
    }
}

pub fn save_vex(doc: &CycloneDxVex, dest: &Utf8Path) -> crate::Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }

    let json_content = serde_json::to_string_pretty(doc)?;
    fs::write(dest, format!("{}\n", json_content))?;

    Ok(())
}

/// Write separate VEX JSON files per state (affected/not_affected/under_investigation).
///
/// The provided `vex_out` path is treated as a handle to derive the output directory:
/// - If it is a directory, files are written inside it.
/// - If it is a file path, its parent directory is used.
///
/// Filenames: vex_affected.json, vex_not_affected.json, vex_under_investigation.json
/// States with zero entries are skipped.
pub fn write_split_vex_output(vex_entries: Vec<VexEntry>, vex_out: &Utf8Path) -> crate::Result<()> {
    let out_dir = if vex_out.is_dir() {
        vex_out.to_path_buf()
    } else {
        vex_out
            .parent()
            .unwrap_or_else(|| Utf8Path::new("."))
            .to_path_buf()
    };

    // Ensure output directory exists
    fs::create_dir_all(&out_dir)?;

    // Group entries by state
    let mut by_state: HashMap<String, Vec<VexEntry>> = HashMap::new();
    by_state.insert("affected".to_string(), Vec::new());
    by_state.insert("not_affected".to_string(), Vec::new());
    by_state.insert("under_investigation".to_string(), Vec::new());

    for entry in vex_entries {
        by_state.entry(entry.state.clone()).or_default().push(entry);
    }

    let mut written = Vec::new();

    // Write VEX documents for each state that has entries
    for (state, entries) in by_state {
        if entries.is_empty() {
            continue;
        }

        let doc = build_vex(entries.clone(), None, None);
        let out_file = out_dir.join(format!("vex_{}.json", state));
        save_vex(&doc, &out_file)?;
        written.push((state, out_file, entries.len()));
    }

    // Log summary
    if written.is_empty() {
        info!("No VEX entries to write");
    } else {
        let summary: Vec<String> = written
            .iter()
            .map(|(state, _, count)| format!("{}:{}", state, count))
            .collect();
        info!(
            "Wrote VEX state files: {} -> {}",
            summary.join(", "),
            out_dir
        );
    }

    Ok(())
}
