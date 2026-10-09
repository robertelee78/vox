//! `vox-theme swift <tokens.json> <out-dir>`: write the macOS app's asset catalogue and Swift
//! tokens from the one token file (ADR-028 L-1). The app's build runs it; nothing else defines a
//! colour, a typeface or a motion value.

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [verb, tokens, out] = args.as_slice() else {
        eprintln!("usage: vox-theme swift <tokens.json> <out-dir>");
        return ExitCode::from(2);
    };
    if verb != "swift" {
        eprintln!("vox-theme: unknown verb {verb:?}; the one verb is `swift`");
        return ExitCode::from(2);
    }
    let tokens = match vox_theme::load(Path::new(tokens)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("vox-theme: {e}");
            return ExitCode::FAILURE;
        }
    };
    match vox_theme::write_swift(&tokens, Path::new(out)) {
        Ok(()) => {
            println!(
                "vox-theme: wrote {} colours, {} faces, {} motion values, {} spacing steps and {} radii to {}",
                tokens.colors.len(),
                tokens.fonts.len(),
                tokens.motion.len(),
                tokens.space.len(),
                tokens.radius.len(),
                out
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("vox-theme: writing {out}: {e}");
            ExitCode::FAILURE
        }
    }
}
