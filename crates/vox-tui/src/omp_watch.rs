//! Read-only daemon availability observation and OMP lifetime ownership.
use std::io::{BufRead, Read, Write};
use std::time::Duration;
use tokio::sync::mpsc;
use vox_core::node::daemonipc::{DaemonClient, DaemonFrame, DaemonRequest, NodeState};
use vox_core::node::paths::{Account, NodeName};
use crate::omp_fence::{FenceError, Owner};
use crate::wake::AttentionRoute;

const DEADLINE: Duration = Duration::from_secs(2);
const MAX_LINE: u64 = 65536;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    id: String,
    op: String,
    generation: Option<String>,
    session: Option<String>,
    endpoint: Option<String>,
    token: Option<String>,
    route: Option<String>,
}

fn output(value: serde_json::Value) -> bool {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value).is_ok() && stdout.write_all(b"\n").is_ok() && stdout.flush().is_ok()
}
fn ack(id: &str, result: Result<(), &str>) -> bool {
    match result {
        Ok(()) => output(serde_json::json!({"type":"ack","id":id,"ok":true})),
        Err(reason) => output(serde_json::json!({"type":"ack","id":id,"ok":false,"reason":reason})),
    }
}
fn input() -> mpsc::Receiver<Option<Vec<u8>>> {
    let (tx, rx) = mpsc::channel(1);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        loop {
            let mut line = Vec::new();
            let n = std::io::Read::by_ref(&mut input).take(MAX_LINE + 1).read_until(b'\n', &mut line);
            match n {
                Ok(0) | Err(_) => std::process::exit(0),
                Ok(_) if line.len() as u64 > MAX_LINE || !line.ends_with(b"\n") => std::process::exit(1),
                Ok(_) => if tx.blocking_send(Some(line)).is_err() { break; },
            }
        }
    });
    rx
}
fn fingerprint(account: &Account, node: &NodeName) -> Option<vox_core::hash::Digest32> {
    account.node_paths_as_they_are(node).shown_fingerprint()
}
fn pin(owner: &Owner, account: &Account, node: &NodeName) -> Result<Option<vox_core::hash::Digest32>, FenceError> {
    let Some(fp) = fingerprint(account, node) else { return Ok(None); };
    owner.pin(&vox_core::node::link::b32_encode(&fp))?;
    Ok(Some(fp))
}
fn selected(client: &DaemonClient, node: &NodeName, fingerprint: &vox_core::hash::Digest32) -> bool {
    client.attached.iter().any(|entry| entry.name == *node && entry.state == NodeState::Attached && entry.fingerprint.as_ref() == Some(fingerprint))
}
#[derive(Clone, Copy)]
enum ProbeError { Unavailable, Mismatch }
async fn open(account: &Account) -> Result<DaemonClient, ProbeError> {
    // Observe the authenticated pid/version before applying the strict open check.
    let greeting = tokio::time::timeout(DEADLINE, DaemonClient::observe(&account.socket())).await;
    match greeting {
        Ok(Ok(g)) if g.protocol != vox_core::node::ipc::PROTOCOL_VERSION || g.version != env!("CARGO_PKG_VERSION") => return Err(ProbeError::Mismatch),
        Ok(Ok(_)) => (),
        Ok(Err(vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Protocol { .. } | vox_core::error::IpcHandshake::Version { .. }))) => return Err(ProbeError::Mismatch),
        _ => return Err(ProbeError::Unavailable),
    }
    match tokio::time::timeout(DEADLINE, DaemonClient::open(&account.socket())).await {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Protocol { .. } | vox_core::error::IpcHandshake::Version { .. }))) => Err(ProbeError::Mismatch),
        _ => Err(ProbeError::Unavailable),
    }
}
struct Subscription {
    pid: u32,
    events: mpsc::Receiver<()>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Subscription {
    fn drop(&mut self) { self.task.abort(); }
}

async fn snapshot(account: &Account, node: &NodeName, fp: &vox_core::hash::Digest32, subscription: &mut Option<Subscription>) -> Result<bool, ProbeError> {
    let initial = open(account).await?;
    if !selected(&initial, node, fp) { *subscription = None; return Ok(false); }
    drop(initial);
    if subscription.is_none() {
        let mut sub = open(account).await?;
        let pid = sub.pid;
        match tokio::time::timeout(DEADLINE, sub.request(DaemonRequest::Subscribe)).await {
            Ok(Ok(DaemonFrame::Ok)) => {
                let (tx, events) = mpsc::channel(1);
                let task = tokio::spawn(async move {
                    loop {
                        match sub.next().await {
                            Ok(Some(DaemonFrame::Event(_))) => { let _ = tx.try_send(()); }
                            _ => break,
                        }
                    }
                });
                *subscription = Some(Subscription { pid, events, task });
            }
            _ => return Err(ProbeError::Unavailable),
        }
    }
    // Subscribe was acknowledged first. Recheck whenever an event arrived during the hello.
    let until = tokio::time::Instant::now() + DEADLINE;
    loop {
        if tokio::time::Instant::now() >= until { return Err(ProbeError::Unavailable); }
        let fresh = open(account).await?;
        if subscription.as_ref().is_none_or(|sub| sub.pid != fresh.pid) { return Err(ProbeError::Unavailable); }
        let ready = selected(&fresh, node, fp);
        drop(fresh);
        let Some(sub) = subscription.as_mut() else { return Err(ProbeError::Unavailable); };
        match sub.events.try_recv() {
            Err(mpsc::error::TryRecvError::Empty) => { if !ready { *subscription = None; } return Ok(ready); }
            Ok(()) => continue,
            Err(mpsc::error::TryRecvError::Disconnected) => return Err(ProbeError::Unavailable),
        }
    }
}
fn decode_route(command: &Command) -> Option<AttentionRoute> {
    let hex = command.route.as_deref()?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return None; }
    let mut route = [0; 32];
    for (i, byte) in route.iter_mut().enumerate() { *byte = u8::from_str_radix(&hex[i*2..i*2+2], 16).ok()?; }
    Some(AttentionRoute { endpoint: command.endpoint.clone()?, token: command.token.clone()?, route })
}
fn reason(e: FenceError) -> &'static str { match e { FenceError::Busy => "busy", FenceError::Invalid => "invalid" } }

pub(crate) async fn run(account: Account, node: NodeName, successor: bool, instance: Option<String>) -> u8 {
    let mut input = input();
    let owner = loop {
        match Owner::acquire(&account, instance.as_deref()) {
            Ok(owner) => break owner,
            Err(FenceError::Busy) if instance.is_some() => tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(250)) => (),
                _ = input.recv() => return 1,
            },
            Err(_) => return 1,
        }
    };
    if !output(serde_json::json!({"type":"owner","instance":owner.instance_id})) { return 1; }
    let mut mismatch_consumed = successor;
    let mut saw_mismatch = successor;
    let mut compatible = false;
    let mut last_command = 0u64;
    let mut subscription: Option<Subscription> = None;
    let mut pinned = pin(&owner, &account, &node).ok().flatten();
    let mut delay = 0u64;
    let mut backoff = 1u64;
    let mut snapshot_id: Option<String> = None;
    loop {
        let timer = tokio::time::sleep(Duration::from_secs(delay));
        tokio::pin!(timer);
        tokio::select! {
            item = input.recv() => {
                let Some(Some(line)) = item else { return 0; };
                let Ok(command) = serde_json::from_slice::<Command>(&line) else { return 1; };
                if command.id.is_empty() || command.id.len() > 128 { return 1; }
                let Ok(sequence) = command.id.parse::<u64>() else { return 1; };
                if sequence <= last_command { if !ack(&command.id, Err("invalid")) { return 1; } continue; }
                last_command = sequence;
                match command.op.as_str() {
                    "revoke" => if !ack(&command.id, owner.revoke().map_err(reason)) { return 1; },
                    "install" => {
                        let pin_result = pin(&owner, &account, &node);
                        if pinned.is_none() { pinned = pin_result.as_ref().ok().copied().flatten(); }
                        let result = match (pin_result, pinned, command.generation.clone(), command.session.clone(), decode_route(&command)) {
                            (Ok(Some(current)), Some(fp), Some(generation), Some(session), Some(route)) if current == fp => {
                                owner.install(generation, vox_core::node::link::b32_encode(&fp), session, route).map_err(reason)
                            },
                            (Ok(None), _, _, _, _) => Err("busy"),
                            (Err(error), _, _, _, _) => Err(reason(error)),
                            _ => Err("invalid"),
                        };
                        if !ack(&command.id, result) { return 1; }
                    }
                    "snapshot" => {
                        if snapshot_id.is_some() { if !ack(&command.id, Err("busy")) { return 1; } }
                        else { snapshot_id = Some(command.id); delay = 0; }
                    }
                    _ => if !ack(&command.id, Err("invalid")) { return 1; },
                }
            }
            event = async { match subscription.as_mut() { Some(sub) => sub.events.recv().await, None => std::future::pending().await } } => {
                match event { Some(()) => delay = 0, None => { subscription = None; delay = backoff; backoff = (backoff * 2).min(30); if !output(serde_json::json!({"type":"unavailable","reason":"unavailable"})) { return 1; } } }
            }
            _ = &mut timer => {
                if pinned.is_none() { pinned = pin(&owner, &account, &node).ok().flatten(); }
                let result = match pinned {
                    Some(fp) if fingerprint(&account, &node) == Some(fp) => snapshot(&account, &node, &fp, &mut subscription).await,
                    _ => { subscription = None; match open(&account).await { Err(e) => Err(e), Ok(_) => Ok(false) } }
                };
                if result.is_ok() {
                    mismatch_consumed = false;
                    if saw_mismatch {
                        saw_mismatch = false;
                        if !output(serde_json::json!({"type":"matched"})) { return 1; }
                    }
                }
                match result {
                    Ok(true) => {
                        if !compatible {
                            if owner.set_compatible(true).is_err() {
                                if let Some(id) = snapshot_id.take() { if !ack(&id, Err("unavailable")) { return 1; } }
                                if !output(serde_json::json!({"type":"unavailable","reason":"unavailable"})) { return 1; }
                                delay = backoff; backoff = (backoff * 2).min(30);
                                continue;
                            }
                            compatible = true;
                        }
                        if let Some(id) = snapshot_id.take() { if !ack(&id, Ok(())) { return 1; } }
                        if !output(serde_json::json!({"type":"ready"})) { return 1; }
                        delay = 30; backoff = 1;
                    }
                    other => {
                        subscription = None;
                        let mismatch = matches!(other, Err(ProbeError::Mismatch));
                        if mismatch && compatible {
                            if owner.set_compatible(false).is_err() { return 1; }
                            compatible = false;
                        }
                        if mismatch { saw_mismatch = true; }
                        if let Some(id) = snapshot_id.take() { if !ack(&id, Err("unavailable")) { return 1; } }
                        if !output(serde_json::json!({"type":"unavailable","reason":if mismatch { "mismatch" } else { "unavailable" }})) { return 1; }
                        if mismatch && !mismatch_consumed { return 76; }
                        delay = backoff; backoff = (backoff * 2).min(30);
                    }
                }
            }
        }
    }
}
