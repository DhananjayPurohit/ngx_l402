fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_files = &["proto/content.proto"];
    let include_dirs = &["proto"];
    let out_dir = std::env::var("OUT_DIR").unwrap();

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(format!("{}/content_descriptor.bin", out_dir))
        .compile(proto_files, include_dirs)?;

    // Generate Rust code for the file descriptor set
    let descriptor_set = std::fs::read(format!("{}/content_descriptor.bin", out_dir))?;
    let code = format!(
        "pub const FILE_DESCRIPTOR_SET: &[u8] = &{:?};",
        descriptor_set
    );
    std::fs::write(format!("{}/content_descriptor.rs", out_dir), code)?;

    Ok(())
}
