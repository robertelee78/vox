//! ADR-051: change one real ELF version-need name and establish the loader's refusal.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Command;

fn number(bytes: &[u8], offset: usize, width: usize) -> usize {
    let mut value = [0_u8; 8];
    value[..width].copy_from_slice(
        bytes
            .get(offset..offset + width)
            .expect("APPARATUS: truncated ELF table"),
    );
    usize::try_from(u64::from_le_bytes(value)).expect("APPARATUS: oversized ELF offset")
}

fn text(bytes: &[u8], offset: usize) -> &str {
    let tail = bytes.get(offset..).expect("APPARATUS: ELF string offset");
    let length = tail
        .iter()
        .position(|byte| *byte == 0)
        .expect("APPARATUS: unterminated ELF string");
    std::str::from_utf8(&tail[..length]).expect("APPARATUS: ELF name is not text")
}

fn version(path: &Path, scratch: &Path) -> std::process::Output {
    Command::new(path)
        .arg("--version")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", scratch)
        .env("VOX_DATA_DIR", scratch.join("data"))
        .env("VOX_CONFIG_DIR", scratch.join("config"))
        .output()
        .expect("APPARATUS: run dead-candidate staging check")
}

/// Return the impossible GLIBC name, after proving the real source runs and the altered copy
/// fails with that exact loader diagnostic. No product check is replaced or bypassed.
pub fn stage(source: &Path, destination: &Path) -> String {
    let scratch = destination
        .parent()
        .expect("APPARATUS: candidate directory");
    let original = version(source, scratch);
    assert!(
        original.status.success() && original.stdout.starts_with(b"vox "),
        "APPARATUS: dead candidate source did not run: {}{}",
        String::from_utf8_lossy(&original.stdout),
        String::from_utf8_lossy(&original.stderr)
    );
    let mut bytes = std::fs::read(source).expect("APPARATUS: read ELF source");
    assert!(
        bytes.starts_with(b"\x7fELF\x02\x01"),
        "APPARATUS: source is not little-endian ELF64"
    );
    let section_offset = number(&bytes, 40, 8);
    let section_width = number(&bytes, 58, 2);
    let section_count = number(&bytes, 60, 2);
    let names = section_offset + number(&bytes, 62, 2) * section_width;
    let names = number(&bytes, names + 24, 8);
    let section = |wanted: &str| {
        (0..section_count)
            .map(|i| section_offset + i * section_width)
            .find(|offset| text(&bytes, names + number(&bytes, *offset, 4)) == wanted)
            .unwrap_or_else(|| panic!("APPARATUS: missing ELF section {wanted}"))
    };
    let needs_section = section(".gnu.version_r");
    let strings = section_offset + number(&bytes, needs_section + 40, 4) * section_width;
    let strings = number(&bytes, strings + 24, 8);
    let symbols = section(".dynsym");
    let symbol_offset = number(&bytes, symbols + 24, 8);
    let symbol_width = number(&bytes, symbols + 56, 8);
    let symbol_count = number(&bytes, symbols + 32, 8) / symbol_width;
    let versions = number(&bytes, section(".gnu.version") + 24, 8);
    let mut needs = std::collections::BTreeMap::new();
    let mut offset = number(&bytes, needs_section + 24, 8);
    loop {
        if text(&bytes, strings + number(&bytes, offset + 4, 4)) == "libc.so.6" {
            let mut aux = offset + number(&bytes, offset + 8, 4);
            for _ in 0..number(&bytes, offset + 2, 2) {
                needs.insert(
                    number(&bytes, aux + 6, 2) & 0x7fff,
                    (strings + number(&bytes, aux + 8, 4), 0_usize),
                );
                let next = number(&bytes, aux + 12, 4);
                if next == 0 {
                    break;
                }
                aux += next;
            }
        }
        let next = number(&bytes, offset + 12, 4);
        if next == 0 {
            break;
        }
        offset += next;
    }
    for index in 0..symbol_count {
        let symbol = symbol_offset + index * symbol_width;
        if bytes[symbol + 4] >> 4 != 2 && number(&bytes, symbol + 6, 2) == 0 {
            if let Some((_, count)) =
                needs.get_mut(&(number(&bytes, versions + index * 2, 2) & 0x7fff))
            {
                *count += 1;
            }
        }
    }
    let (name_offset, count) = needs
        .into_values()
        .max_by_key(|(_, count)| *count)
        .expect("APPARATUS: libc has no version needs");
    assert!(count > 0, "APPARATUS: no non-weak libc symbol references");
    let old = text(&bytes, name_offset).to_owned();
    let numeric = old
        .strip_prefix("GLIBC_")
        .expect("APPARATUS: libc need has no GLIBC prefix");
    assert!(
        numeric.as_bytes().get(1) == Some(&b'.') && numeric.as_bytes()[0].is_ascii_digit(),
        "APPARATUS: libc major version cannot be rewritten in place: {old}"
    );
    bytes[name_offset + 6] = b'9';
    let impossible = text(&bytes, name_offset).to_owned();
    std::fs::write(destination, bytes).expect("APPARATUS: write dead ELF copy");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o755))
        .expect("APPARATUS: make dead candidate executable");
    let dead = version(destination, scratch);
    assert!(
        !dead.status.success()
            && String::from_utf8_lossy(&dead.stderr)
                .contains(&format!("version `{impossible}' not found")),
        "APPARATUS: the dead candidate was not staged: {}{}",
        String::from_utf8_lossy(&dead.stdout),
        String::from_utf8_lossy(&dead.stderr)
    );
    impossible
}

/// Run an installer or updater for at most 40 seconds. The bound is the proof's guard;
/// the product must return on its own and leave none of its observed sleep children running.
pub fn bounded(command: &mut Command) -> (std::process::Output, bool, Vec<u32>) {
    use std::io::{Read as _, Seek as _};
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let mut stdout = tempfile::tempfile().expect("APPARATUS: stdout receipt");
    let mut stderr = tempfile::tempfile().expect("APPARATUS: stderr receipt");
    let mut child = command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone().expect("APPARATUS: stdout clone"))
        .stderr(stderr.try_clone().expect("APPARATUS: stderr clone"))
        .spawn()
        .expect("APPARATUS: start bounded command");
    let mut descendants = std::collections::BTreeSet::from([child.id()]);
    let mut sleepers = std::collections::BTreeSet::new();
    let started = Instant::now();
    let mut timely = true;
    let status = loop {
        let processes: Vec<_> = std::fs::read_dir("/proc")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let pid = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
                let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
                let fields = stat
                    .rsplit_once(')')?
                    .1
                    .split_whitespace()
                    .collect::<Vec<_>>();
                let parent = fields.get(1)?.parse::<u32>().ok()?;
                Some((pid, parent))
            })
            .collect();
        loop {
            let old = descendants.len();
            for (pid, parent) in &processes {
                if descendants.contains(parent) {
                    descendants.insert(*pid);
                }
            }
            if old == descendants.len() {
                break;
            }
        }
        for pid in &descendants {
            if std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .is_ok_and(|name| name.trim() == "sleep")
            {
                sleepers.insert(*pid);
            }
        }
        if let Some(status) = child.try_wait().expect("APPARATUS: wait bounded command") {
            break status;
        }
        if started.elapsed() > Duration::from_secs(40) {
            timely = false;
            for pid in &descendants {
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", &pid.to_string()])
                    .status();
            }
            break child.wait().expect("APPARATUS: reap bounded command");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let running = |pid: &u32| {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
            stat.rsplit_once(')')
                .is_some_and(|(_, fields)| !fields.trim_start().starts_with('Z'))
        })
    };
    let leaked: Vec<_> = sleepers.into_iter().filter(running).collect();
    for pid in &leaked {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    let (mut out, mut err) = (Vec::new(), Vec::new());
    stdout.rewind().expect("APPARATUS: rewind stdout");
    stderr.rewind().expect("APPARATUS: rewind stderr");
    stdout
        .read_to_end(&mut out)
        .expect("APPARATUS: read stdout");
    stderr
        .read_to_end(&mut err)
        .expect("APPARATUS: read stderr");
    (
        std::process::Output {
            status,
            stdout: out,
            stderr: err,
        },
        timely,
        leaked,
    )
}
