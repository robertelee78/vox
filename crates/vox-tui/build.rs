//! Turns the one token file (`assets/theme/vox-tokens.json`, ADR-028 L-1) into the TUI's colour
//! and motion constants, so the TUI defines no colour of its own. A token file this build cannot
//! read stops the build with the reason.

use std::path::PathBuf;

fn main() {
    let manifest =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let tokens = manifest.join("../../assets/theme/vox-tokens.json");
    println!("cargo:rerun-if-changed={}", tokens.display());
    let parsed = match vox_theme::load(&tokens) {
        Ok(t) => t,
        Err(e) => panic!("the token file cannot be read: {e}"),
    };
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"))
        .join("theme_tokens.rs");
    std::fs::write(&out, vox_theme::rust_source(&parsed))
        .expect("cannot write the generated tokens");
}
