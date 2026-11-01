fn main() {
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rerun-if-changed=src/filesystem.m");
        println!("cargo:rustc-link-lib=framework=Foundation");
        cc::Build::new()
            .file("src/filesystem.m")
            .compile("vox_macos_fs");
    }
}
