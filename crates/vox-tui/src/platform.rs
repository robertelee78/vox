//! **The machine a node runs on, as its sessions' `hello` says it** (ADR-020 §4.9b): its OS, OS
//! version and CPU architecture, so a session choosing who to hand work to can see which machine
//! each one runs on. Vox fills them from the machine, never the model; a reader shows them as that
//! node's own claim.

use serde_json::{Map, Value};

/// The `hello`'s `data` key for the OS: `macOS`, `Linux`, or Rust's name for any other.
pub const OS_KEY: &str = "os";
/// The `hello`'s `data` key for the OS version: macOS's product version (`26.2`), a Linux
/// distribution's `PRETTY_NAME` (`Ubuntu 24.04.1 LTS`), else its `VERSION_ID`; `""` when the machine
/// does not say.
pub const OS_VERSION_KEY: &str = "os_version";
/// The `hello`'s `data` key for the CPU architecture, as Rust names it: `aarch64`, `x86_64`.
pub const ARCH_KEY: &str = "arch";

/// The most characters of each field a reader shows: another node's claim is its own text.
const SHOWN: usize = 48;

/// This machine's OS.
#[must_use]
pub fn os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macOS",
        "linux" => "Linux",
        other => other,
    }
}

/// This machine's OS version, or `""` when it does not say.
#[must_use]
pub fn os_version() -> String {
    if cfg!(target_os = "macos") {
        std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist")
            .ok()
            .and_then(|plist| plist_string(&plist, "ProductVersion"))
            .unwrap_or_default()
    } else {
        std::fs::read_to_string("/etc/os-release")
            .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
            .ok()
            .and_then(|release| {
                os_release(&release, "PRETTY_NAME").or_else(|| os_release(&release, "VERSION_ID"))
            })
            .unwrap_or_default()
    }
}

/// The `<string>` after `<key>{key}</key>` in a property list.
fn plist_string(plist: &str, key: &str) -> Option<String> {
    let after = &plist[plist.find(&format!("<key>{key}</key>"))?..];
    let start = after.find("<string>")? + "<string>".len();
    let end = after[start..].find("</string>")?;
    Some(after[start..start + end].trim().to_owned()).filter(|v| !v.is_empty())
}

/// `key`'s value in an os-release file, its quotes taken off.
fn os_release(release: &str, key: &str) -> Option<String> {
    release
        .lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_owned())
        .filter(|v| !v.is_empty())
}

/// Put this machine's OS, OS version and architecture into a `hello`'s `data`.
pub fn insert(data: &mut Map<String, Value>) {
    data.insert(OS_KEY.into(), os().into());
    data.insert(OS_VERSION_KEY.into(), os_version().into());
    data.insert(ARCH_KEY.into(), std::env::consts::ARCH.into());
}

/// What a `hello`'s `data` says of its machine, for a person: `macOS 26.2 (aarch64)`. `None` for a
/// hello that says nothing of it (a node before ADR-020 §4.9b).
#[must_use]
pub fn claim(data: &Value) -> Option<String> {
    let field = |key: &str| {
        data.get(key)
            .and_then(Value::as_str)
            .map(|v| vox_text::shown(v.trim(), SHOWN))
            .filter(|v| !v.is_empty())
    };
    let os = field(OS_KEY);
    let version = field(OS_VERSION_KEY);
    let arch = field(ARCH_KEY);
    if os.is_none() && version.is_none() && arch.is_none() {
        return None;
    }
    let mut said = [os, version]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(arch) = arch {
        said = if said.is_empty() {
            arch
        } else {
            format!("{said} ({arch})")
        };
    }
    Some(said)
}

/// A `hello`'s machine fields as they came, for JSON: `{"os", "os_version", "arch"}`, each `null`
/// when the hello did not say.
#[must_use]
pub fn fields(data: &Value) -> Value {
    let field = |key: &str| data.get(key).and_then(Value::as_str).map(str::to_owned);
    serde_json::json!({
        OS_KEY: field(OS_KEY),
        OS_VERSION_KEY: field(OS_VERSION_KEY),
        ARCH_KEY: field(ARCH_KEY),
    })
}
