use camino::Utf8PathBuf;
use kcfg_vex::cve::{build_vex, save_vex, VexEntry};
use tempfile::TempDir;

#[test]
fn test_vex_generation() {
    let entries = vec![
        VexEntry::new(
            "CVE-2023-1234".to_string(),
            "not_affected".to_string(),
            "This vulnerability does not affect the configured kernel".to_string(),
            Some("vulnerable_code_not_present".to_string()),
            vec!["linux-kernel".to_string()],
        ),
        VexEntry::new(
            "CVE-2023-5678".to_string(),
            "under_investigation".to_string(),
            "Impact assessment ongoing".to_string(),
            None,
            vec!["linux-kernel".to_string()],
        ),
    ];

    let vex_doc = build_vex(entries, Some("1.4".to_string()), None);

    assert_eq!(vex_doc.bom_format, "CycloneDX");
    assert_eq!(vex_doc.spec_version, "1.4");
    assert_eq!(vex_doc.version, 1);
    assert_eq!(vex_doc.vulnerabilities.len(), 2);

    // Check first vulnerability (not_affected with justification)
    let vuln1 = &vex_doc.vulnerabilities[0];
    assert_eq!(vuln1.id, "CVE-2023-1234");
    assert_eq!(vuln1.analysis.state, "not_affected");
    assert_eq!(
        vuln1.analysis.justification,
        Some("vulnerable_code_not_present".to_string())
    );

    // Check second vulnerability (under_investigation, no justification)
    let vuln2 = &vex_doc.vulnerabilities[1];
    assert_eq!(vuln2.id, "CVE-2023-5678");
    assert_eq!(vuln2.analysis.state, "under_investigation");
    assert_eq!(vuln2.analysis.justification, None);
}

#[test]
fn test_vex_save() {
    let temp_dir = TempDir::new().unwrap();
    let vex_path = Utf8PathBuf::from_path_buf(temp_dir.path().join("test.vex.json"))
        .expect("Invalid UTF-8 in path");

    let entries = vec![VexEntry::new(
        "CVE-2023-1234".to_string(),
        "affected".to_string(),
        "Vulnerability confirmed in kernel version".to_string(),
        None,
        vec!["linux-kernel".to_string()],
    )];

    let vex_doc = build_vex(entries, None, None);
    save_vex(&vex_doc, &vex_path).unwrap();

    assert!(vex_path.exists());

    // Verify the saved file can be read as valid JSON
    let content = std::fs::read_to_string(&vex_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(parsed["bomFormat"], "CycloneDX");
    assert_eq!(parsed["vulnerabilities"][0]["id"], "CVE-2023-1234");
}
