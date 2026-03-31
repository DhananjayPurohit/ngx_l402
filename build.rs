fn main() {
    // On macOS, nginx modules need to allow undefined symbols
    // since nginx will provide them at runtime when loading the module
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-cdylib-link-arg=-undefined");
        println!("cargo:rustc-cdylib-link-arg=dynamic_lookup");
    }
}
