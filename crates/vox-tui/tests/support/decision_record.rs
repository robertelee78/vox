//! A node's decision record (ADR-028 §7), read as its person's clients read it: through the
//! daemon, which alone opens it (#563), as the TUI's Decisions screen and the app ask for it. The
//! day files under `<data root>/nodes/<node>/decisions/` are sealed; [`files`] gives their bytes
//! for a proof to search for what must not be in them.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Where node `node`'s decision record is, under the data root `data`.
pub fn dir(data: &Path, node: &str) -> PathBuf {
    data.join("nodes").join(node).join("decisions")
}

/// Every event in the record, oldest first, as node `node`'s daemon at the data root `data` answers
/// for it ([`vox_core::node::ipc::Request::Decisions`]), each as the JSON object an event is:
/// `at_ms`, `asked`, `by`, `alias`, `decided`, `why`, and `room` when it has one. A node the daemon
/// does not hold has no record to read: an empty one.
pub fn events(data: &Path, node: &str) -> Vec<serde_json::Value> {
    use vox_core::node::ipc::{Frame, IpcClient, NodeSocket, Request};
    let socket = vox_core::node::paths::Account::of(Some(data), Some(&data.join("cfg")))
        .expect("APPARATUS: the data root's account")
        .socket();
    let name = vox_core::node::paths::NodeName::parse(node).expect("APPARATUS: a node name");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: a runtime");
    let asked = rt.block_on(async {
        let mut client = IpcClient::open_at(&NodeSocket::one_shot(socket, name))
            .await
            .ok()?;
        client
            .request(&Request::Decisions { limit: u64::MAX })
            .await
            .ok()
    });
    let Some(Frame::Decisions { events }) = asked else {
        return Vec::new();
    };
    let mut out: Vec<serde_json::Value> = events
        .into_iter()
        .map(|e| {
            let mut v = serde_json::json!({
                "at_ms": e.at_ms, "asked": e.asked, "by": e.by, "alias": e.alias,
                "decided": e.decided, "why": e.why,
            });
            if let Some(room) = e.room {
                v["room"] = room.into();
            }
            v
        })
        .collect();
    out.reverse();
    out
}

/// Every day file of the record, by name, with its bytes as text (lossy); none when there is no
/// record.
pub fn files(data: &Path, node: &str) -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir(dir(data, node)) else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = entries
        .flatten()
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                String::from_utf8_lossy(&std::fs::read(e.path()).unwrap_or_default()).into_owned(),
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
