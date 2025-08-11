use camino::Utf8PathBuf;
use kcfg_vex::kernel::tracer::trace_kernel_config;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_tracer_basic_functionality() {
    let temp_dir = TempDir::new().unwrap();
    let src_root =
        Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("Invalid UTF-8 in path");

    // Create a simple kernel source structure
    let drivers_dir = src_root.join("drivers").join("net");
    fs::create_dir_all(&drivers_dir).unwrap();

    // Create a source file
    let src_file = drivers_dir.join("test_driver.c");
    fs::write(&src_file, "/* Test driver source */").unwrap();

    // Create a Makefile with basic config
    let makefile = drivers_dir.join("Makefile");
    let makefile_content = r#"
obj-$(CONFIG_TEST_DRIVER) += test_driver.o
obj-$(CONFIG_ANOTHER_DRIVER) += another_driver.o
"#;
    fs::write(&makefile, makefile_content).unwrap();

    // Test without enabled symbols filter
    let result = trace_kernel_config("drivers/net/test_driver.c", &src_root).unwrap();

    assert_eq!(result.file, "drivers/net/test_driver.c");
    assert!(result.objects.contains("test_driver.o"));
    assert!(result.symbols.contains("CONFIG_TEST_DRIVER"));
    assert!(result.error.is_none());
    assert!(!result.edges.is_empty());
}

#[test]
fn test_tracer_container_objects() {
    let temp_dir = TempDir::new().unwrap();
    let src_root =
        Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("Invalid UTF-8 in path");

    let drivers_dir = src_root.join("drivers").join("complex");
    fs::create_dir_all(&drivers_dir).unwrap();

    // Create source files
    let src_file = drivers_dir.join("component.c");
    fs::write(&src_file, "/* Component source */").unwrap();

    // Create Makefile with container objects
    let makefile = drivers_dir.join("Makefile");
    let makefile_content = r#"
obj-$(CONFIG_COMPLEX_DRIVER) += complex-driver.o
complex-driver-objs := component.o helper.o
complex-driver-objs-$(CONFIG_FEATURE_X) += feature_x.o
"#;
    fs::write(&makefile, makefile_content).unwrap();

    let result = trace_kernel_config("drivers/complex/component.c", &src_root).unwrap();

    // Should find both the component and container
    assert!(result.objects.contains("component.o"));
    assert!(result.objects.contains("complex-driver.o"));
    assert!(result.symbols.contains("CONFIG_COMPLEX_DRIVER"));

    // Check that we have proper edges explaining the relationships
    let has_container_edge = result.edges.iter().any(|edge| {
        edge.via == "container includes target" && edge.dst.contains("complex-driver.o")
    });
    assert!(
        has_container_edge,
        "Should have container relationship edge"
    );
}

#[test]
fn test_tracer_parent_directory_scanning() {
    let temp_dir = TempDir::new().unwrap();
    let src_root =
        Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("Invalid UTF-8 in path");

    // Create nested directory structure
    let parent_dir = src_root.join("drivers");
    let child_dir = parent_dir.join("submodule");
    fs::create_dir_all(&child_dir).unwrap();

    // Create source file in child directory
    let src_file = child_dir.join("module.c");
    fs::write(&src_file, "/* Module source */").unwrap();

    // Create child Makefile
    let child_makefile = child_dir.join("Makefile");
    fs::write(&child_makefile, "obj-y += module.o").unwrap();

    // Create parent Makefile that gates the subdirectory
    let parent_makefile = parent_dir.join("Makefile");
    let parent_content = r#"
obj-$(CONFIG_PARENT_MODULE) += submodule/
obj-$(CONFIG_PARENT_MODULE) += submodule/module.o
"#;
    fs::write(&parent_makefile, parent_content).unwrap();

    let result = trace_kernel_config("drivers/submodule/module.c", &src_root).unwrap();

    // Should find the parent gate config
    assert!(result.symbols.contains("CONFIG_PARENT_MODULE"));
}

#[test]
fn test_tracer_missing_file() {
    let temp_dir = TempDir::new().unwrap();
    let src_root =
        Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("Invalid UTF-8 in path");

    let result = trace_kernel_config("nonexistent/file.c", &src_root).unwrap();

    assert!(result.error.is_some());
    assert!(result.error.as_ref().unwrap().contains("File not found"));
    assert!(result.symbols.is_empty());
    assert!(result.objects.is_empty());
}

#[test]
fn test_tracer_with_makefile_files() {
    let temp_dir = TempDir::new().unwrap();
    let src_root =
        Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("Invalid UTF-8 in path");

    let drivers_dir = src_root.join("drivers").join("makefile_test");
    fs::create_dir_all(&drivers_dir).unwrap();

    let src_file = drivers_dir.join("makefile_module.c");
    fs::write(&src_file, "/* Makefile module */").unwrap();

    // Use Makefile
    let makefile = drivers_dir.join("Makefile");
    let makefile_content = r#"
obj-$(CONFIG_MAKEFILE_MODULE) += makefile_module.o
"#;
    fs::write(&makefile, makefile_content).unwrap();

    let result = trace_kernel_config("drivers/makefile_test/makefile_module.c", &src_root).unwrap();

    assert!(result.symbols.contains("CONFIG_MAKEFILE_MODULE"));
    assert!(result.objects.contains("makefile_module.o"));
}
