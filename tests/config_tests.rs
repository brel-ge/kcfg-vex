use camino::Utf8PathBuf;
use kcfg_vex::kernel::DotConfig;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_dotconfig_parsing() {
    let temp_dir = TempDir::new().unwrap();
    let config_path =
        Utf8PathBuf::from_path_buf(temp_dir.path().join(".config")).expect("Invalid UTF-8 in path");

    let config_content = r#"
# Linux/x86 4.19.0 Kernel Configuration
CONFIG_X86=y
CONFIG_64BIT=y
CONFIG_X86_64=y
# CONFIG_X86_32 is not set
CONFIG_SMP=y
CONFIG_MODULE_SUPPORT=m
# CONFIG_BROKEN is not set
    "#;

    fs::write(&config_path, config_content).unwrap();

    let config = DotConfig::from_path(&config_path).unwrap();

    assert!(config.is_enabled("CONFIG_X86", false));
    assert!(config.is_enabled("CONFIG_64BIT", false));
    assert!(!config.is_enabled("CONFIG_X86_32", false));
    assert!(!config.is_enabled("CONFIG_BROKEN", false));

    // Test module support
    assert!(!config.is_enabled("CONFIG_MODULE_SUPPORT", false));
    assert!(config.is_enabled("CONFIG_MODULE_SUPPORT", true));

    let enabled_set = config.enabled_set(false);
    assert!(enabled_set.contains("CONFIG_X86"));
    assert!(enabled_set.contains("CONFIG_64BIT"));
    assert!(!enabled_set.contains("CONFIG_MODULE_SUPPORT"));

    let enabled_set_with_modules = config.enabled_set(true);
    assert!(enabled_set_with_modules.contains("CONFIG_MODULE_SUPPORT"));
}

#[test]
fn test_dotconfig_from_text() {
    let config_content = r#"
CONFIG_TEST=y
# CONFIG_DISABLED is not set
CONFIG_MODULE=m
    "#;

    let config = DotConfig::from_text(config_content).unwrap();

    assert!(config.is_enabled("CONFIG_TEST", false));
    assert!(!config.is_enabled("CONFIG_DISABLED", false));
    assert!(config.is_enabled("CONFIG_MODULE", true));
    assert!(!config.is_enabled("CONFIG_MODULE", false));
}
