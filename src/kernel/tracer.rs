use camino::{Utf8Path, Utf8PathBuf};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::OnceLock;
use tracing::{debug, info};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceEdge {
    pub src: String,
    pub dst: String,
    pub via: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResult {
    pub file: String,
    pub objects: HashSet<String>,
    pub symbols: HashSet<String>,
    pub edges: Vec<TraceEdge>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
struct ScanResult {
    configs_for_target: HashSet<String>,
    containers: HashSet<String>,
}

// Static regex patterns
struct RegexPatterns {
    whitespace: Regex,
    container_name: &'static str,
}

impl RegexPatterns {
    fn get() -> &'static Self {
        static PATTERNS: OnceLock<RegexPatterns> = OnceLock::new();
        PATTERNS.get_or_init(|| RegexPatterns {
            whitespace: Regex::new(r"\s+").unwrap(),
            container_name: r"[A-Za-z0-9_-]+",
        })
    }
}

pub(crate) fn extract_program_files_from_cve(cve_data: &serde_json::Value) -> Vec<String> {
    let mut files = Vec::new();

    if let Some(containers) = cve_data.get("containers") {
        if let Some(cna) = containers.get("cna") {
            if let Some(affected) = cna.get("affected").and_then(|v| v.as_array()) {
                for aff in affected {
                    if let Some(program_files) = aff.get("programFiles").and_then(|v| v.as_array())
                    {
                        for file in program_files {
                            if let Some(file_str) = file.as_str() {
                                // Strip leading "./" if present
                                let clean_file = file_str.trim_start_matches("./");
                                files.push(clean_file.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Remove duplicates and sort
    files.sort();
    files.dedup();
    files
}

pub fn trace_kernel_config(rel_file: &str, src_root: &Utf8PathBuf) -> crate::Result<TraceResult> {
    let start_time = std::time::Instant::now();
    info!("Starting trace for file: {}", rel_file);

    let rel = rel_file.trim().trim_start_matches("./");
    let src_path = src_root.join(rel);

    if !src_path.exists() {
        debug!("File not found: {} (checked path: {})", rel_file, src_path);
        return Ok(TraceResult {
            file: rel_file.to_string(),
            objects: HashSet::new(),
            symbols: HashSet::new(),
            edges: Vec::new(),
            error: Some(format!("File not found in source tree: {}", src_path)),
        });
    }

    let obj_name = src_path.file_name().unwrap().replace(".c", ".o");
    let file_dir = src_path.parent().unwrap();

    // Build relative path from file_dir to src_root for target matching
    let rel_from_makefile_dir =
        if let Ok(relative) = src_path.with_extension("o").strip_prefix(file_dir) {
            Some(relative.to_string())
        } else {
            None
        };

    let mut symbols = HashSet::new();
    let mut objects = HashSet::new();
    let mut edges = Vec::new();

    objects.insert(obj_name.clone());

    // Unified BFS algorithm: Single queue handles all targets (local + parent directories)
    // Queue contains (target, directory, subdir_hint, source_target) tuples
    let mut processing_queue = vec![(
        obj_name.clone(),
        file_dir.to_path_buf(),
        None,
        obj_name.clone(),
    )];
    let mut visited_containers = std::collections::HashSet::new();

    // Add initial file with relative path if different
    if let Some(ref rel_path) = rel_from_makefile_dir {
        if rel_path != &obj_name {
            processing_queue.push((
                rel_path.clone(),
                file_dir.to_path_buf(),
                None,
                obj_name.clone(),
            ));
        }
    }

    // Add parent directory targets to initial queue
    let mut scan_child = file_dir.to_path_buf();
    let mut parent = scan_child.parent();
    while let Some(parent_dir) = parent {
        if !is_within(parent_dir, src_root) || parent_dir == src_root {
            break;
        }

        let parent_rel_target = object_path_relative_to(&src_path, parent_dir);
        let subdir = scan_child.file_name().unwrap().to_string();

        processing_queue.push((
            parent_rel_target,
            parent_dir.to_path_buf(),
            Some(subdir),
            obj_name.clone(),
        ));

        scan_child = parent_dir.to_path_buf();
        parent = scan_child.parent();
    }

    // Process all targets with unified BFS
    while !processing_queue.is_empty() {
        let current_batch = processing_queue.clone();
        processing_queue.clear();

        for (target, directory, subdir_hint, source_target) in current_batch {
            // Skip if already processed
            let container_key = format!("{}@{}", target, directory);
            if visited_containers.contains(&container_key) {
                continue;
            }
            visited_containers.insert(container_key);

            // Scan makefile for this target
            if let Some(makefile_path) = get_makefile_path(&directory) {
                let scan_result =
                    scan_makefile_for_targets(&makefile_path, &target, subdir_hint.as_deref())?;

                // Add found CONFIG symbols
                for config in &scan_result.configs_for_target {
                    symbols.insert(config.clone());
                    let via = if subdir_hint.is_some() {
                        "parent directory gate"
                    } else {
                        "makefile rule"
                    };
                    edges.push(TraceEdge {
                        src: format!("{}@{}", source_target, file_dir),
                        dst: format!("CONFIG:{}", config),
                        via: via.to_string(),
                    });
                }

                // Add containers to process
                for container in &scan_result.containers {
                    if !objects.contains(container) {
                        objects.insert(container.clone());
                        let via = if subdir_hint.is_some() {
                            "parent container includes target"
                        } else {
                            "container includes target"
                        };
                        edges.push(TraceEdge {
                            src: format!("{}@{}", target, directory),
                            dst: format!("{}@{}", container, directory),
                            via: via.to_string(),
                        });
                        processing_queue.push((
                            container.clone(),
                            directory.clone(),
                            None,
                            source_target.clone(),
                        ));
                    }
                }
            }
        }
    }

    let total_time = start_time.elapsed();
    info!(
        "Trace completed for {} in {:?}: {} symbols, {} objects, {} edges",
        rel_file,
        total_time,
        symbols.len(),
        objects.len(),
        edges.len()
    );

    Ok(TraceResult {
        file: rel_file.to_string(),
        objects,
        symbols,
        edges,
        error: None,
    })
}

fn get_makefile_path(directory: &Utf8Path) -> Option<Utf8PathBuf> {
    let path = directory.join("Makefile");
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

fn is_within(path: &Utf8Path, src_root: &Utf8Path) -> bool {
    path.starts_with(src_root)
}

fn object_path_relative_to(src_path: &Utf8Path, ancestor_dir: &Utf8Path) -> String {
    match src_path.with_extension("o").strip_prefix(ancestor_dir) {
        Ok(rel_path) => rel_path.as_str().to_string(),
        Err(_) => src_path
            .with_extension("o")
            .file_name()
            .unwrap()
            .to_string(),
    }
}

fn read_makefile_lines(path: &Utf8Path) -> crate::Result<Vec<String>> {
    read_makefile_lines_no_cache(path)
}

fn read_makefile_lines_no_cache(path: &Utf8Path) -> crate::Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(path)?;
    let raw_lines: Vec<&str> = content.lines().collect();

    // Join backslash-continued lines
    let mut joined = Vec::new();
    let mut buf = String::new();

    for line in raw_lines {
        let s = line.trim_end();
        if let Some(stripped) = s.strip_suffix('\\') {
            buf.push_str(stripped);
            buf.push(' ');
        } else {
            buf.push_str(s);
            joined.push(buf.clone());
            buf.clear();
        }
    }
    if !buf.is_empty() {
        joined.push(buf);
    }

    // Strip and compact whitespace
    let patterns = RegexPatterns::get();
    let mut result = Vec::new();
    for line in joined {
        let compressed = patterns.whitespace.replace_all(&line, " ");
        let trimmed = compressed.trim();
        if !trimmed.is_empty() {
            result.push(trimmed.to_string());
        }
    }

    Ok(result)
}

fn scan_makefile_for_targets(
    makefile_path: &Utf8Path,
    target: &str,
    subdir: Option<&str>,
) -> crate::Result<ScanResult> {
    let lines = read_makefile_lines(makefile_path)?;
    let mut configs_for_target = HashSet::new();
    let mut containers = HashSet::new();

    if target.is_empty() {
        return Ok(ScanResult {
            configs_for_target,
            containers,
        });
    }

    let makefile_content = lines.join(" ");
    let targets_mentioned = makefile_content.contains(target);

    if !targets_mentioned && subdir.is_none() {
        // No targets found in Makefile and no subdir to check - skip expensive regex processing
        return Ok(ScanResult {
            configs_for_target,
            containers,
        });
    }

    // Build target pattern and create regexes inline
    let escaped_target = regex::escape(target);
    let target_pattern = format!(r"(?:{})", escaped_target);

    // Create regex patterns
    let patterns = RegexPatterns::get();
    let container_name = patterns.container_name;

    let obj_config_pattern = format!(
        r"\bobj-\$\((CONFIG_[A-Z0-9_]+)\)\s*\+?=\s.*\b{}\b",
        target_pattern
    );
    let container_config_pattern = format!(
        r"\b({})-(?:y|m|\$\((CONFIG_[A-Z0-9_]+)\))\s*[:+]?=\s.*\b{}\b",
        container_name, target_pattern
    );
    let container_objs_pattern = format!(
        r"\b({})-objs\s*[:+]?=\s.*\b{}\b",
        container_name, target_pattern
    );
    let container_objs_config_pattern = format!(
        r"\b({})-objs-\$\((CONFIG_[A-Z0-9_]+)\)\s*[:+]?=\s.*\b{}\b",
        container_name, target_pattern
    );

    let obj_config_regex = Regex::new(&obj_config_pattern).ok();
    let container_config_regex = Regex::new(&container_config_pattern).ok();
    let container_objs_regex = Regex::new(&container_objs_pattern).ok();
    let container_objs_config_regex = Regex::new(&container_objs_config_pattern).ok();

    for line in &lines {
        if targets_mentioned {
            // 1) obj-$(CONFIG_FOO) += <target>
            if let Some(ref regex) = obj_config_regex {
                if let Some(captures) = regex.captures(line) {
                    if let Some(config) = captures.get(1) {
                        configs_for_target.insert(config.as_str().to_string());
                    }
                }
            }

            // 2) <container>-(y|m|$(CONFIG_BAR)) += <target>
            if let Some(ref regex) = container_config_regex {
                if let Some(captures) = regex.captures(line) {
                    if let Some(container) = captures.get(1) {
                        containers.insert(format!("{}.o", container.as_str()));
                    }
                    if captures.len() > 2 {
                        if let Some(config) = captures.get(2) {
                            configs_for_target.insert(config.as_str().to_string());
                        }
                    }
                }
            }

            // 3) <container>-objs :=/+= <target>
            if let Some(ref regex) = container_objs_regex {
                if let Some(captures) = regex.captures(line) {
                    if let Some(container) = captures.get(1) {
                        containers.insert(format!("{}.o", container.as_str()));
                    }
                }
            }

            // 4) <container>-objs-$(CONFIG_BAZ) :=/+= <target>
            if let Some(ref regex) = container_objs_config_regex {
                if let Some(captures) = regex.captures(line) {
                    if let Some(container) = captures.get(1) {
                        containers.insert(format!("{}.o", container.as_str()));
                    }
                    if let Some(config) = captures.get(2) {
                        configs_for_target.insert(config.as_str().to_string());
                    }
                }
            }
        }

        // 5) directory gating: obj-$(CONFIG_QUX) += subdir/
        if let Some(subdir_name) = subdir {
            let subdir_escaped = regex::escape(&format!("{}/", subdir_name.trim_end_matches('/')));
            let dir_gate_pattern = format!(
                r"\bobj-\$\((CONFIG_[A-Z0-9_]+)\)\s*[:+]?=\s.*\b{}\b",
                subdir_escaped
            );
            if let Ok(regex) = Regex::new(&dir_gate_pattern) {
                if let Some(captures) = regex.captures(line) {
                    if let Some(config) = captures.get(1) {
                        // Directory gate found - add to configs_for_target
                        configs_for_target.insert(config.as_str().to_string());
                    }
                }
            }
        }
    }

    Ok(ScanResult {
        configs_for_target,
        containers,
    })
}
