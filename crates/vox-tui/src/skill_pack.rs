//! The agent skill pack (ADR-029 §7): what an agent reads to work in a Vox room — rooms, Sessions,
//! trust, files and setup — as one entry (`SKILL.md`) and the reference files it points to, put
//! where each harness loads a user-scope skill, `<skills>/vox-agent-comms/`.
//!
//! **Installed without the operator doing anything** (v0.4.1): `install.sh` and `vox update` run
//! `vox agent skill --install`, which installs or refreshes the pack for every harness present here.
//! It is idempotent, and it never overwrites a file the operator changed: what it wrote is recorded
//! in the folder's manifest (`.vox-pack.json`, each file's SHA-256), and a file that no longer
//! matches what Vox wrote is left alone and named. A `SKILL.md` written before the pack, by `vox
//! setup` or by hand from `vox agent skill`, is refreshed when it is exactly a version Vox shipped
//! ([`EARLIER`]), else kept. `vox setup` installs the same way.

use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

/// The folder the pack is installed in, under a harness's skills folder.
pub const DIR_NAME: &str = "vox-agent-comms";

/// The manifest of what Vox wrote into the folder.
pub const MANIFEST: &str = ".vox-pack.json";

/// The pack: each file's path in the folder, and what it holds.
pub const FILES: &[(&str, &str)] = &[
    ("SKILL.md", include_str!("../assets/skill/SKILL.md")),
    (
        "references/rooms.md",
        include_str!("../assets/skill/references/rooms.md"),
    ),
    (
        "references/sessions.md",
        include_str!("../assets/skill/references/sessions.md"),
    ),
    (
        "references/trust.md",
        include_str!("../assets/skill/references/trust.md"),
    ),
    (
        "references/files.md",
        include_str!("../assets/skill/references/files.md"),
    ),
    (
        "references/setup.md",
        include_str!("../assets/skill/references/setup.md"),
    ),
];

/// The SHA-256 of every `SKILL.md` Vox shipped before the pack (the single `agent-skill.md`, each
/// version in the repository's history): such a file, untouched, is Vox's to refresh.
const EARLIER: &[&str] = &[
    "00216c4160707f791def05b24cb22c7bf85f6d972bb8b3b4ab90b72dfc831764",
    "01d7dc20f3659ecc5877e277b2696ed4e25c54224ae55e158506de95fe4fb777",
    "1bb9b646c9e4ad71c0ebdcbaa1ff2b150a714ffc32191c5adf31428dfc88a3d4",
    "1e87daeb93a9409aeca7bc2f13428e52f21d9d63b0fa17060f808f31445a4817",
    "1ff0eb59e453b302e79d8b63eb5be82ebc29e013a0b5941f5b135dea8083d302",
    "28276ed5fc8a0723dbae3da721993bef8667c22e299bf99847a17567d6618d84",
    "29c1e55b23499f6de3a839f315e0d08146a276205ebc548e1b4081b414835ee8",
    "2d77fefd786c5a8149e6f8c30c189a3ff59ed34abe2cdc7048754248393e6b65",
    "2fd421a8682bca3a6c1ec2845570703f5d7bdec493bdcadaf6317c96b2194261",
    "3cef15483106ee138a12dee842f6552d5c69395da5e2083be6f92bf33d87558e",
    "40b2c9e17a3b0b7ca47ebff5e43d65fa26baeffe2faa2d0062bcb4c33f9d8c6e",
    "44ff7e22c223386765d09b98faaf8744f4565099473aebe0f4062014f58e3bb0",
    "46d8095fc636b89cbe1c570f41b9e29fe0a4be2b337e71d1e7fccbd6f409d2cb",
    "47c5b40e22359f44841596259843c5edc10dccaae2f00c1effbf8fc8b49693ac",
    "4d951133790370253518ad06141d4b87cbe626f64fc622921a001103443b918a",
    "52d930637f7b8f8191648fb266f8afe7a6121c566a98bf0f60db903514ad769d",
    "5b4de46e80085a669e7664049f9bad29c8cad90b53b3ecaf54d145b5156cf1ca",
    "5c50db08ea62e8e6a02977c62d16483d73608e56381bbfa0352aa50241629995",
    "5d9c79e0680415019b704ad535acd5116c3a7f0b3b711420aa7a07dbf54dcbf7",
    "627176463ef9373429a8ee7da5d0d2d1ce264e16131e586589eacc77fd4bcdc9",
    "7a586d79d66bded682db8bec29259e15692873d73e2a3984160ed6a5db0f8e90",
    "892d3b7b20a69a1d38b127c6dfe66953505aab19c390bc766be1cffd5e9202b6",
    "8c58bb1df4ffd2a2dd1bb39bd5d5ffd747ae788c3100b49e1e1c91a5c4ba7918",
    "9604a98358712eb906af7f64c8c7fab2f47faba2f40fa8f088c55ebc76ff0807",
    "9c6dc8b9a14ad68fb2aafa316c39f72cfab3b18563bddbaca02e99b082a64318",
    "a0822a764d0dd61043b6594f70e1f53bcf1e8abe40f52659563eb49eba2ac2bd",
    "a855e6789bc9f367d1989466df5b32482e26cc6349efdc0abbae359aa7bc064f",
    "b15053d3aa377caa313bd10ebf2e66e64385d70bdd247d301484932602062d43",
    "b4654cc3c1a72e64b6af33db11da1cc83f5691c5b4547b9e283392fb85ecda51",
    "b97c20df1f7f585b0c1c8c72e2e0fc68de588425531acbf9c52af5b95eebe5f0",
    "b9cc682b762c23abddf3b0e9419d117544b47dcb9ded02a7b01fc70cc2d9c29e",
    "c3b2c2aea22523de7b779affc62118619a979cd4f240e269dd6d80867ad52124",
    "c47544d3124bdd2bc2c3b5322c15e7e29583a414415cb5f3d9a6513de3bd9db7",
    "cc3f578b8b385cad8775b83c3d69f76bdfbbe08217faf4a211a9faf798766fe1",
    "da8b6ff0055daa964271b3890d856c3a94ce54bfaa888aa69f827881b4d6bcda",
    "de73be8151a0596d43a37b07c270e3d1cd7fec4ec6cd6fbec1cbb9619e50ec25",
    "e09641e334f3b38e1b98d5645e5975d7b7b976e2f9ef127f66896b80f7e3ece5",
    "eaaa0bf2c7e11ba1eb71106d638e6fd23edf0baac433212eec11417bdb4f3d1a",
    "f78ca8963c12a17e3c3b8296147f27e7e480fd9fc36bb620144907b1c3d131fb",
    "fd3b194800f1df651b6ab0a6789f85da3d7bfaa03d3389eb5ad2e6a2d7964aee",
];

/// A harness Vox installs the pack for.
pub struct Harness {
    /// How `vox agent` names it.
    pub key: &'static str,
    /// How a person names it.
    pub name: &'static str,
    /// Its program, looked for on `PATH`.
    pub program: &'static str,
}

/// The harnesses, in the order they are reported.
pub const HARNESSES: [Harness; 3] = [
    Harness {
        key: "claude",
        name: "Claude Code",
        program: "claude",
    },
    Harness {
        key: "codex",
        name: "Codex",
        program: "codex",
    },
    Harness {
        key: "opencode",
        name: "OpenCode",
        program: "opencode",
    },
];

fn var(v: &str) -> Option<PathBuf> {
    std::env::var_os(v)
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
}

/// The harness's own configuration folder, as it finds it: `$CLAUDE_CONFIG_DIR` or `~/.claude`;
/// `$CODEX_HOME` or `~/.codex`; `$OPENCODE_CONFIG_DIR`, `$XDG_CONFIG_HOME/opencode` or
/// `~/.config/opencode`. `None` with no `HOME`.
#[must_use]
pub fn config_dir(key: &str) -> Option<PathBuf> {
    let home = || var("HOME");
    match key {
        "claude" => var("CLAUDE_CONFIG_DIR").or_else(|| home().map(|h| h.join(".claude"))),
        "codex" => var("CODEX_HOME").or_else(|| home().map(|h| h.join(".codex"))),
        _ => var("OPENCODE_CONFIG_DIR")
            .or_else(|| var("XDG_CONFIG_HOME").map(|x| x.join("opencode")))
            .or_else(|| home().map(|h| h.join(".config").join("opencode"))),
    }
}

/// Where the pack goes for `key`: `<config>/skills/vox-agent-comms`.
#[must_use]
pub fn pack_dir(key: &str) -> Option<PathBuf> {
    config_dir(key).map(|d| d.join("skills").join(DIR_NAME))
}

/// Whether harness `h` is present here: its program on `PATH`, or its configuration folder there.
#[must_use]
pub fn present(h: &Harness) -> bool {
    config_dir(h.key).is_some_and(|d| d.is_dir()) || on_path(h.program)
}

fn on_path(program: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|d| {
            std::fs::metadata(d.join(program))
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What installing did to one file of the pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Done {
    /// Written where there was none.
    Installed(PathBuf),
    /// Written over what Vox wrote before, untouched since.
    Refreshed(PathBuf),
    /// Already what this Vox ships.
    Current(PathBuf),
    /// Left alone: it changed since Vox wrote it, or Vox did not write it.
    Kept(PathBuf),
}

impl Done {
    /// The line a person reads.
    #[must_use]
    pub fn said(&self) -> String {
        match self {
            Done::Installed(p) => format!("installed {}", p.display()),
            Done::Refreshed(p) => format!("refreshed {}", p.display()),
            Done::Current(p) => format!("{} is current", p.display()),
            Done::Kept(p) => format!(
                "left {} as it is: it was changed after Vox installed it, so Vox does not \
                 overwrite it (delete it and run `vox agent skill --install` to take this \
                 version's)",
                p.display()
            ),
        }
    }
}

/// Install or refresh the pack in `dir`, file by file, keeping any file the operator changed.
///
/// # Errors
/// A file or the manifest cannot be written.
pub fn install_into(dir: &Path) -> std::io::Result<Vec<Done>> {
    std::fs::create_dir_all(dir.join("references"))?;
    let manifest_path = dir.join(MANIFEST);
    let recorded: serde_json::Map<String, serde_json::Value> = std::fs::read(&manifest_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("files").and_then(|f| f.as_object()).cloned())
        .unwrap_or_default();
    let mut written = serde_json::Map::new();
    let mut done = Vec::new();
    for (rel, content) in FILES {
        let path = dir.join(rel);
        let ours = sha256_hex(content.as_bytes());
        let now = std::fs::read(&path).ok().map(|b| sha256_hex(&b));
        // Vox wrote what is there now: by its manifest, or, before there was one, as a version of
        // the single skill it shipped.
        let vox_wrote = |h: &str| {
            recorded.get(*rel).and_then(|v| v.as_str()) == Some(h)
                || (*rel == "SKILL.md" && recorded.is_empty() && EARLIER.contains(&h))
        };
        match now.as_deref() {
            Some(h) if h == ours => {
                written.insert((*rel).to_owned(), ours.into());
                done.push(Done::Current(path));
            }
            None => {
                std::fs::write(&path, content)?;
                written.insert((*rel).to_owned(), ours.into());
                done.push(Done::Installed(path));
            }
            Some(h) if vox_wrote(h) => {
                std::fs::write(&path, content)?;
                written.insert((*rel).to_owned(), ours.into());
                done.push(Done::Refreshed(path));
            }
            Some(_) => {
                // What Vox wrote here before stays on record, so the file stays known as changed.
                if let Some(h) = recorded.get(*rel) {
                    written.insert((*rel).to_owned(), h.clone());
                }
                done.push(Done::Kept(path));
            }
        }
    }
    let manifest = serde_json::json!({
        "pack": DIR_NAME,
        "vox": env!("CARGO_PKG_VERSION"),
        "files": written,
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    )?;
    Ok(done)
}

/// `vox agent skill --install`: the pack for every harness present here, said line by line.
/// Returns whether it was installed for every harness present.
#[must_use]
pub fn install_all() -> bool {
    let mut ok = true;
    for h in &HARNESSES {
        if !present(h) {
            println!(
                "vox: {}: not found here, so no skill is installed for it",
                h.name
            );
            continue;
        }
        let Some(dir) = pack_dir(h.key) else {
            println!(
                "vox: {}: HOME is not set, so its skills folder cannot be found",
                h.name
            );
            ok = false;
            continue;
        };
        match install_into(&dir) {
            Ok(done) => {
                for d in done {
                    println!("vox: {}: {}", h.name, d.said());
                }
            }
            Err(e) => {
                println!(
                    "vox: {}: the skill could not be installed in {}: {e}",
                    h.name,
                    dir.display()
                );
                ok = false;
            }
        }
    }
    ok
}
