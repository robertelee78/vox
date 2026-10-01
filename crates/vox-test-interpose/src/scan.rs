//! **Memory scan on cue** (V210-94, #288): look through every readable page of this process for
//! secret bytes a proof names, and say where they are.
//!
//! A lock is to leave no copy of a passphrase or a key behind, live or freed. No userspace test
//! can read another process's memory on macOS without privileges, but code loaded into the process
//! can read its own. So, with `VOX_INTERPOSE_SCAN` naming a directory, this library starts one
//! thread that waits for a file `go` there. On it, the thread:
//!
//! 1. reads the needles from `needles`, one per line: `label<TAB>hex`, where `hex` is the needle's
//!    bytes each XORed with [`MASK`], so the needle never sits in this process in the clear
//!    because of the scan;
//! 2. walks every region `mach_vm_region_recurse` reports as readable, writable and touched
//!    (resident or swapped out), copying it out a chunk at a
//!    time with `mach_vm_read_overwrite` (which fails, rather than faults, on a page that went
//!    away) into a buffer of its own that is skipped and wiped;
//! 3. writes `result`: a line `count<TAB>label<TAB>n` per needle, then up to [`MAX_HITS`] lines
//!    `hit<TAB>label<TAB>address(hex)<TAB>user_tag<TAB>protection`, and a last line
//!    `scanned<TAB>bytes<TAB>regions`; written to `result.tmp` and renamed, so a reader never sees
//!    half of it. `go` is removed first, so a proof can ask again.
//!
//! The `user_tag` says what the memory is: 30 a thread stack, 1–11 the allocator's zones (7 tiny,
//! 2 small, 3 large, 11 nano). Unset, nothing starts.

use std::ffi::c_int;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Each needle byte is XORed with this in the `needles` file and while held here.
pub const MASK: u8 = 0xA5;
/// Hits listed in `result`, at most; the count is always whole.
const MAX_HITS: usize = 64;
/// How much of a region is copied out at a time.
const CHUNK: usize = 1 << 20;
const VM_PROT_READ: c_int = 1;
const VM_PROT_WRITE: c_int = 2;
const VM_REGION_SUBMAP_INFO_COUNT_64: u32 = 19;

extern "C" {
    fn task_self_trap() -> u32;
    fn mach_vm_region_recurse(
        task: u32,
        address: *mut u64,
        size: *mut u64,
        depth: *mut u32,
        info: *mut u32,
        count: *mut u32,
    ) -> c_int;
    fn mach_vm_read_overwrite(
        task: u32,
        address: u64,
        size: u64,
        data: u64,
        out: *mut u64,
    ) -> c_int;
    fn mmap(addr: *mut u8, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> c_int;
}

/// Start the scanning thread once per process, if `VOX_INTERPOSE_SCAN` names a directory.
pub fn start_once() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(start);
}

fn start() {
    let Some(dir) = std::env::var_os("VOX_INTERPOSE_SCAN") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let _ = std::thread::Builder::new()
        .name("vox-interpose-scan".into())
        .spawn(move || loop {
            let go = dir.join("go");
            if go.exists() {
                let _ = std::fs::remove_file(&go);
                let report = scan(&needles(&dir.join("needles")));
                let tmp = dir.join("result.tmp");
                if std::fs::write(&tmp, report).is_ok() {
                    let _ = std::fs::rename(&tmp, dir.join("result"));
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        });
}

/// The needles, still masked: `(label, masked bytes)`.
fn needles(path: &Path) -> Vec<(String, Vec<u8>)> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let (label, hex) = l.split_once('\t')?;
            let bytes: Option<Vec<u8>> = (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok())
                .collect();
            let bytes = bytes?;
            (!bytes.is_empty()).then(|| (label.to_owned(), bytes))
        })
        .collect()
}

/// Scan every readable region for every needle; the report `result` holds.
fn scan(needles: &[(String, Vec<u8>)]) -> String {
    let longest = needles.iter().map(|(_, n)| n.len()).max().unwrap_or(1);
    // A buffer of its own, in its own mapping, so it can be skipped: what it holds is a copy
    // of what is being scanned.
    // SAFETY: an anonymous private mapping; checked for failure below.
    let buf = unsafe { mmap(std::ptr::null_mut(), CHUNK, 3, 0x1002, -1, 0) };
    if buf as isize == -1 {
        return "error\tmmap\n".to_owned();
    }
    let own = (buf as u64, buf as u64 + CHUNK as u64);
    // This task's own port. (Through the trap, not the `mach_task_self_` global: a Rust
    // extern static of it left the library unloadable, "mis-aligned LINKEDIT string pool".)
    // SAFETY: no preconditions.
    let task = unsafe { task_self_trap() };
    let mut counts = vec![0usize; needles.len()];
    let mut hits = Vec::new();
    let (mut scanned, mut regions) = (0u64, 0u64);
    let mut address: u64 = 0;
    let mut depth: u32 = 0;
    loop {
        let mut size: u64 = 0;
        let mut info = [0u32; VM_REGION_SUBMAP_INFO_COUNT_64 as usize];
        let mut count = VM_REGION_SUBMAP_INFO_COUNT_64;
        // SAFETY: every out-pointer is valid for the size the call writes.
        let kr = unsafe {
            mach_vm_region_recurse(
                task,
                &mut address,
                &mut size,
                &mut depth,
                info.as_mut_ptr(),
                &mut count,
            )
        };
        if kr != 0 {
            break;
        }
        // vm_region_submap_info_64, #pragma pack(4): protection at word 0, user_tag at 5,
        // pages_resident at 6, pages_swapped_out at 8, is_submap at 12.
        let (protection, user_tag, is_submap) = (info[0] as c_int, info[5], info[12] != 0);
        let touched = info[6] != 0 || info[8] != 0;
        if is_submap {
            depth += 1;
            continue;
        }
        // Only memory the process can write, and has touched: a copy of a secret is made by
        // writing it. This leaves out the shared cache's text and constants, and address space
        // reserved and never used, which is most of a process's gigabytes.
        let wanted = protection & (VM_PROT_READ | VM_PROT_WRITE) == VM_PROT_READ | VM_PROT_WRITE;
        if wanted && touched && !(address < own.1 && own.0 < address + size) {
            regions += 1;
            let mut at = address;
            let end = address + size;
            while at < end {
                let want = (end - at).min(CHUNK as u64);
                let mut got: u64 = 0;
                // SAFETY: `buf` is CHUNK bytes of this process's own mapping; the kernel copies at
                // most `want` bytes into it, or fails.
                let kr = unsafe { mach_vm_read_overwrite(task, at, want, buf as u64, &mut got) };
                if kr == 0 {
                    let got = got as usize;
                    // SAFETY: the kernel wrote `got` bytes into `buf`.
                    let chunk = unsafe { std::slice::from_raw_parts(buf, got) };
                    for (k, (label, needle)) in needles.iter().enumerate() {
                        for i in find_all(chunk, needle) {
                            counts[k] += 1;
                            if hits.len() < MAX_HITS {
                                // What surrounds the copy, masked so the report holds no needle
                                // itself: 32 bytes before it and 8 after, within this chunk. It
                                // tells a copy's container apart (a frame, a string, a key).
                                let from = i.saturating_sub(32);
                                let to = (i + needle.len() + 8).min(chunk.len());
                                let around: String = chunk[from..to]
                                    .iter()
                                    .map(|b| format!("{:02x}", b ^ MASK))
                                    .collect();
                                hits.push(format!(
                                    "hit\t{label}\t{:#x}\t{user_tag}\t{protection}\t{}:{around}",
                                    at + i as u64,
                                    i - from
                                ));
                            }
                        }
                    }
                    scanned += got as u64;
                }
                // Overlap by a needle's length, so one lying across two chunks is still found.
                let step = if want as usize > longest {
                    want - longest as u64 + 1
                } else {
                    want
                };
                at += step;
            }
        }
        address += size;
    }
    // SAFETY: `buf` is CHUNK bytes of this function's own mapping.
    unsafe {
        std::ptr::write_bytes(buf, 0, CHUNK);
        munmap(buf, CHUNK);
    }
    let mut out = String::new();
    for ((label, _), n) in needles.iter().zip(&counts) {
        out.push_str(&format!("count\t{label}\t{n}\n"));
    }
    for h in hits {
        out.push_str(&h);
        out.push('\n');
    }
    out.push_str(&format!("scanned\t{scanned}\t{regions}\n"));
    out
}

/// Every offset in `hay` where the unmasked `masked` needle starts.
fn find_all(hay: &[u8], masked: &[u8]) -> Vec<usize> {
    let first = masked[0] ^ MASK;
    let mut found = Vec::new();
    if hay.len() < masked.len() {
        return found;
    }
    for i in 0..=hay.len() - masked.len() {
        if hay[i] == first
            && hay[i..i + masked.len()]
                .iter()
                .zip(masked)
                .all(|(h, m)| *h == *m ^ MASK)
        {
            found.push(i);
        }
    }
    found
}
