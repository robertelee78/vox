//! Native UI proof apparatus: a synthetic member withdraws its own board bundle while
//! remaining connected. The app and the node under proof stay ordinary binaries.
use std::{path::Path, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};
use vox_core::identity::composite::RootSigner;
use vox_core::nat::service::{RecordKinds, RendezvousClient};
use vox_core::nat::withdraw::{BoardWithdraw, WithdrawScope};
use vox_core::node::{link::b32_decode, paths::Paths, profile::Profile};
use vox_core::transport::quic::VoxEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 9 { return Err("expected scratch, data, config, passfile, room, target, status and hold".into()); }
    let scratch = std::fs::canonicalize(&args[1])?;
    for path in [&args[2], &args[3], &args[4], &args[7], &args[8]] {
        let path = std::fs::canonicalize(path)?;
        if !path.starts_with(&scratch) { return Err("apparatus path is outside scratch".into()); }
    }
    let paths = Paths::resolve("fay", Some(Path::new(&args[2])), Some(Path::new(&args[3])))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut profile = loop {
        match Profile::open(paths.clone()) {
            Ok(profile) => break profile,
            Err(_) if std::time::Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(200)).await,
            Err(error) => return Err(error.into()),
        }
    };
    let pass = std::fs::read_to_string(&args[4])?;
    profile.unlock(pass.trim_end().as_bytes())?;
    let signer = profile.signer_arc().ok_or("synthetic member signer unavailable")?;
    let member = signer.fingerprint();
    let room = b32_decode(&args[5], "room id")?;
    let target = b32_decode(&args[6], "target fingerprint")?;
    let status: serde_json::Value = serde_json::from_slice(&std::fs::read(&args[7])?)?;
    let epoch = status["rooms"].as_array().ok_or("target has no room status")?.iter()
        .find(|row| row["id"].as_str() == Some(args[5].as_str()))
        .and_then(|row| row["epoch"].as_u64()).ok_or("target has no matching room epoch")?;
    let addr = status["listening"].as_array().ok_or("target has no listeners")?.iter()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|s| vox_core::nat::multiaddr::Multiaddr::parse(s).ok())
        .filter_map(|a| a.socket_addr())
        .find(|a| a.ip().is_loopback()).ok_or("target has no loopback listener")?;
    let local = if addr.is_ipv6() { "[::1]:0" } else { "127.0.0.1:0" };
    let endpoint = VoxEndpoint::bind(Arc::clone(&signer) as Arc<_>, local.parse()?)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let connection = endpoint.connect(addr, target, now).await?;
    let wire = BoardWithdraw::build(signer.as_ref(), &room, epoch, WithdrawScope::Member, now)?.to_wire();
    let mut client = RendezvousClient::open(&connection).await?;
    client.put(&wire).await?;
    let set = client.get(&room, epoch, RecordKinds::ALL).await?;
    if set.bundles.iter().any(|bundle| bundle.author_id == member) {
        return Err("synthetic member bundle remains on the target board".into());
    }
    client.finish();
    println!("withdraw-ready");
    while Path::new(&args[8]).is_file() { tokio::time::sleep(Duration::from_millis(100)).await; }
    Ok(())
}
