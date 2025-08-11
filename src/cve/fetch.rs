use camino::Utf8Path;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::blocking::Client;
use std::collections::HashMap;
use std::fs;
use std::time::Duration;

pub struct CveFetcher {
    client: Client,
    base_url: String,
}

impl CveFetcher {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: "https://cveawg.mitre.org/api/cve".to_string(),
        }
    }

    pub fn fetch_cve(&self, cve_id: &str) -> crate::Result<serde_json::Value> {
        let url = format!("{}/{}", self.base_url, cve_id);

        let response = self.client.get(&url).send()?;

        if response.status().is_success() {
            let json = response.json::<serde_json::Value>()?;
            Ok(json)
        } else {
            Err(crate::error::KcfgVexError::CveNotFound(cve_id.to_string()))
        }
    }

    pub fn fetch_many_cves(
        &self,
        cve_ids: &[String],
        show_progress: bool,
        cache_dir: Option<&Utf8Path>,
        force: bool,
    ) -> HashMap<String, Result<serde_json::Value, crate::error::KcfgVexError>> {
        let mut results = HashMap::new();

        // Create progress bar if requested
        let progress = if show_progress {
            let pb = ProgressBar::new(cve_ids.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            pb.set_message("Fetching CVEs");
            Some(pb)
        } else {
            None
        };

        for cve_id in cve_ids {
            // Check cache first if not forcing refresh
            if !force {
                if let Some(cache_dir) = cache_dir {
                    if let Ok(cached_data) = self.load_cached(cve_id, cache_dir) {
                        results.insert(cve_id.clone(), Ok(cached_data));
                        if let Some(ref pb) = progress {
                            pb.inc(1);
                        }
                        continue;
                    }
                }
            }

            // Fetch from network
            match self.fetch_cve(cve_id) {
                Ok(data) => {
                    // Save to cache if cache directory is provided
                    if let Some(cache_dir) = cache_dir {
                        let _ = self.save_to_cache(cve_id, &data, cache_dir);
                    }
                    results.insert(cve_id.clone(), Ok(data));
                }
                Err(e) => {
                    results.insert(cve_id.clone(), Err(e));
                }
            }

            if let Some(ref pb) = progress {
                pb.inc(1);
            }
        }

        if let Some(pb) = progress {
            pb.finish_with_message("CVE fetching complete");
        }

        results
    }

    fn load_cached(
        &self,
        cve_id: &str,
        cache_dir: &Utf8Path,
    ) -> Result<serde_json::Value, crate::error::KcfgVexError> {
        let cache_file = cache_dir.join(format!("{}.json", cve_id));
        let content = fs::read_to_string(cache_file)?;
        let json = serde_json::from_str(&content)?;
        Ok(json)
    }

    fn save_to_cache(
        &self,
        cve_id: &str,
        data: &serde_json::Value,
        cache_dir: &Utf8Path,
    ) -> crate::Result<()> {
        // Ensure cache directory exists
        fs::create_dir_all(cache_dir)?;

        let cache_file = cache_dir.join(format!("{}.json", cve_id));
        let content = serde_json::to_string_pretty(data)?;
        fs::write(cache_file, content)?;

        Ok(())
    }
}

impl Default for CveFetcher {
    fn default() -> Self {
        Self::new()
    }
}
