//! A node's decision record (ADR-028 §7), read as its person would read it: the day files under
//! `<data root>/nodes/<node>/decisions/`, one JSON object per line.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Where node `node`'s decision record is, under the data root `data`.
pub fn dir(data: &Path, node: &str) -> PathBuf {
    data.join("nodes").join(node).join("decisions")
}

/// Every event in the record, oldest file first, as written. A line that is not JSON is a red of
/// its own: `PRODUCT:` quoting it.
pub fn events(data: &Path, node: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for (_, text) in files(data, node) {
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            out.push(serde_json::from_str(line).unwrap_or_else(|e| {
                panic!("PRODUCT: a line of the decision record is not JSON ({e}): {line:?}")
            }));
        }
    }
    out
}

/// Every day file of the record, by name, with what it holds; none when there is no record.
pub fn files(data: &Path, node: &str) -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir(dir(data, node)) else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = entries
        .flatten()
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read_to_string(e.path()).unwrap_or_default(),
            )
        })
        .collect();
    out.sort();
    out
}

/// Wait up to `within` for an event `pred` holds of; the record as it then is, and whether one did.
pub fn until(
    data: &Path,
    node: &str,
    within: std::time::Duration,
    pred: impl Fn(&serde_json::Value) -> bool,
) -> (Vec<serde_json::Value>, bool) {
    let t0 = std::time::Instant::now();
    loop {
        let all = events(data, node);
        if all.iter().any(&pred) || t0.elapsed() >= within {
            let found = all.iter().any(&pred);
            return (all, found);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Whether `e` is a decision `decided` about `fp` (a fingerprint as `vox` prints it) on being asked
/// `asked`, with a reason.
pub fn is(e: &serde_json::Value, asked: &str, decided: &str, fp: &str) -> bool {
    e["asked"] == asked
        && e["decided"] == decided
        && e["by"] == fp
        && e["why"].as_str().is_some_and(|w| !w.is_empty())
}

/// `YYYY-MM-DD` of the UTC day `days` after 1970-01-01, as the record names its files.
pub fn date_of(days: i64) -> String {
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Today, in days after 1970-01-01 (UTC).
pub fn today() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("APPARATUS: the clock is before 1970")
        .as_secs();
    i64::try_from(secs / 86_400).expect("APPARATUS: a day count past i64")
}
