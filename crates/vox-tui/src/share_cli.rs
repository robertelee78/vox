//! `vox share` (PRD-001 R18, ADR-020 §11) — offer a file or a folder to a room, pulled
//! by whoever wants it with any tool.
//!
//! The bytes never enter the log. They are served over a **room-bound HTTP service**, and
//! what goes on the log is a signed announcement carrying the name, the size and the
//! **SHA-256** — the machinery `vox room send` already uses, with HTTP on top so the
//! receiver can use `curl` (or `rsync`, or a browser) through `vox up` as easily as `vox
//! room get`:
//!
//! ```text
//! curl --socks5-hostname 127.0.0.1:1080 http://<you>.<room>.vox:<port>/<name> -o <name>
//! ```
//!
//! A folder is served as one deterministic tar (sorted, zero timestamps), so it has one
//! hash like a file does.
//!
//! The offer ends after `--count` completed fetches, after `--for` (`90s`, `10m`, `2h`),
//! or on ^C, whichever comes first. The announcement outlives it: a member who wakes late
//! learns it was offered and is told plainly that it can no longer be collected.
//!
//! Reach is the keyring's, as for any room-bound service: a member this node has not
//! trusted can neither read the announcement nor open the service.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use vox_agentcomms::envelope::Envelope;
use vox_core::node::ipc::{Frame, Request};
use vox_core::node::link::b32_encode;
use vox_core::node::paths::Paths;

use crate::app::AppError;
use crate::room_cli::{attach, digest_file, post, room_of, FILE};

/// Parse `90s`, `10m`, `2h` or a bare number of seconds.
///
/// # Errors
/// A duration that is none of those.
pub fn parse_for(text: &str) -> Result<Duration, String> {
    let t = text.trim();
    let (num, unit) = t.split_at(t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len()));
    let n: u64 = num
        .parse()
        .map_err(|_| format!("{text:?} is not a duration (90s, 10m, 2h)"))?;
    let secs = match unit {
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        _ => return Err(format!("{text:?} is not a duration (90s, 10m, 2h)")),
    };
    Ok(Duration::from_secs(secs))
}

/// The port a share is served on, which is also its service tag: derived from the
/// content, so offering the same bytes twice lands on the same port and two different
/// offers almost never collide. Always above 10 000 and a valid port.
fn port_of(sha256: &str) -> u16 {
    let n = u16::from_str_radix(&sha256[..4], 16).unwrap_or(0);
    10_000 + n % 55_000
}

/// Write `dir` as a ustar archive at `out`: entries in sorted order, every timestamp,
/// owner and mode fixed, so the same folder always makes the same bytes and the same
/// hash.
fn tar_dir(dir: &Path, out: &Path) -> Result<(), AppError> {
    fn entries(
        root: &Path,
        dir: &Path,
        acc: &mut Vec<(String, PathBuf, bool)>,
    ) -> std::io::Result<()> {
        let mut list: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
        list.sort_by_key(std::fs::DirEntry::file_name);
        for e in list {
            let path = e.path();
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let ty = e.file_type()?;
            if ty.is_dir() {
                acc.push((format!("{rel}/"), path.clone(), true));
                entries(root, &path, acc)?;
            } else if ty.is_file() {
                acc.push((rel, path, false));
            }
            // Symlinks and devices are not carried: a share is files.
        }
        Ok(())
    }
    let io = |e: std::io::Error| AppError::Usage(format!("archiving {}: {e}", dir.display()));
    let base = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "share".into());
    let mut list = vec![(format!("{base}/"), dir.to_owned(), true)];
    let mut inner = Vec::new();
    entries(dir, dir, &mut inner).map_err(io)?;
    list.extend(
        inner
            .into_iter()
            .map(|(rel, p, d)| (format!("{base}/{rel}"), p, d)),
    );
    let mut f = std::fs::File::create(out).map_err(io)?;
    for (name, path, is_dir) in list {
        let size = if is_dir {
            0
        } else {
            std::fs::metadata(&path).map_err(io)?.len()
        };
        let mut h = [0u8; 512];
        let (prefix, leaf) = if name.len() > 100 {
            let cut = name[..name.len() - 1]
                .rfind('/')
                .filter(|i| *i <= 155 && name.len() - i - 1 <= 100)
                .ok_or_else(|| AppError::Usage(format!("{name}: path too long to archive")))?;
            (&name[..cut], &name[cut + 1..])
        } else {
            ("", name.as_str())
        };
        h[..leaf.len()].copy_from_slice(leaf.as_bytes());
        let octal = |h: &mut [u8], at: usize, len: usize, v: u64| {
            let s = format!("{v:0width$o}", width = len - 1);
            h[at..at + len - 1].copy_from_slice(s.as_bytes());
        };
        octal(&mut h, 100, 8, if is_dir { 0o755 } else { 0o644 });
        octal(&mut h, 108, 8, 0);
        octal(&mut h, 116, 8, 0);
        octal(&mut h, 124, 12, size);
        octal(&mut h, 136, 12, 0);
        h[148..156].copy_from_slice(b"        ");
        h[156] = if is_dir { b'5' } else { b'0' };
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
        let s = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(s.as_bytes());
        f.write_all(&h).map_err(io)?;
        if !is_dir {
            let mut src = std::fs::File::open(&path).map_err(io)?;
            let copied = std::io::copy(&mut src, &mut f).map_err(io)?;
            let pad = (512 - (copied % 512)) % 512;
            f.write_all(&vec![0u8; pad as usize]).map_err(io)?;
        }
    }
    f.write_all(&[0u8; 1024]).map_err(io)?;
    f.flush().map_err(io)
}

/// `vox share <room> <file|dir>`.
pub async fn share(
    paths: &Paths,
    room: &str,
    path: &Path,
    count: Option<u64>,
    for_: Option<Duration>,
) -> Result<(), AppError> {
    let meta =
        std::fs::metadata(path).map_err(|e| AppError::Usage(format!("{}: {e}", path.display())))?;
    let base = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "share".into());
    // A folder becomes one archive beside nothing the person owns: a private temp dir
    // that goes away with this process.
    let staging = tempfile::tempdir().map_err(AppError::Io)?;
    let (served, name) = if meta.is_dir() {
        let tar = staging.path().join(format!("{base}.tar"));
        tar_dir(path, &tar)?;
        (tar, format!("{base}.tar"))
    } else {
        (path.to_owned(), base)
    };
    let (sha256, size) = digest_file(&served)?;
    let port = port_of(&sha256);
    let tag = port.to_string();

    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| AppError::Usage(format!("cannot listen locally: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| AppError::Usage(format!("cannot read the local address: {e}")))?;
    match client
        .request(&Request::AddService {
            channel_id,
            service_tag: tag.clone(),
            local: local.to_string(),
        })
        .await
    {
        Ok(Frame::Ok) => {}
        Ok(Frame::Error { reason }) => {
            return Err(AppError::Usage(format!(
                "cannot offer port {tag}: {reason}"
            )))
        }
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    }
    let env = {
        let mut e = Envelope::new(FILE, &format!("sharing {name} ({size} bytes)"));
        e.data = serde_json::json!({
            "name": name,
            "size": size,
            "sha256": sha256,
            "tag": tag,
            "http": true,
        });
        e
    };
    post(paths, room, Some(&env.to_text())).await?;

    let me = client
        .me()
        .map(|d| b32_encode(&d).chars().take(12).collect::<String>())
        .unwrap_or_default();
    println!("vox: sharing {name} ({size} bytes) on port {port}");
    println!("     sha256 {sha256}");
    println!("     collect it with: vox room get {room} {name}");
    println!(
        "     or through `vox up`: curl --socks5-hostname <proxy> \
         http://<your-name-for-{me}>.<room>.vox:{port}/{name} -o {name}"
    );
    match (count, for_) {
        (Some(n), _) => println!("     stops after {n} fetch(es), or ^C"),
        (None, Some(d)) => println!("     stops after {}s, or ^C", d.as_secs()),
        (None, None) => println!("     ^C stops it; the announcement stays on the log"),
    }

    let fetched = Arc::new(AtomicU64::new(0));
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let deadline = async {
        match for_ {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((sock, _)) = accepted else { continue };
                let (file, name, done) = (served.clone(), name.clone(), done_tx.clone());
                tokio::spawn(async move {
                    if serve_one(sock, &file, &name, size).await {
                        let _ = done.send(());
                    }
                });
            }
            Some(()) = done_rx.recv() => {
                let n = fetched.fetch_add(1, Ordering::SeqCst) + 1;
                println!("vox: fetched {n} time(s)");
                if count.is_some_and(|c| n >= c) {
                    break;
                }
            }
            () = &mut deadline => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    println!(
        "vox: no longer sharing {name} (fetched {} time(s))",
        fetched.load(Ordering::SeqCst)
    );
    let _ = client
        .request(&Request::RemoveService {
            channel_id,
            service_tag: tag,
        })
        .await;
    Ok(())
}

/// Answer one HTTP request with the file. Whatever the path, the answer is the share:
/// there is one thing here. Returns whether every byte went out.
async fn serve_one(mut sock: tokio::net::TcpStream, file: &Path, name: &str, size: u64) -> bool {
    // Read the request head (bounded) so a client that sends one gets a well-formed
    // exchange; the path is not interpreted.
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16 * 1024 {
        match tokio::time::timeout(Duration::from_secs(10), sock.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => head.extend_from_slice(&buf[..n]),
            _ => return false,
        }
    }
    let is_head = head.starts_with(b"HEAD ");
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: \
         {size}\r\nContent-Disposition: attachment; filename=\"{}\"\r\nConnection: close\r\n\r\n",
        name.replace('"', "")
    );
    if sock.write_all(reply.as_bytes()).await.is_err() {
        return false;
    }
    if is_head {
        return false;
    }
    let Ok(mut f) = std::fs::File::open(file) else {
        return false;
    };
    let mut buf = vec![0u8; 64 * 1024];
    let mut sent = 0u64;
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if sock.write_all(&buf[..n]).await.is_err() {
                    return false;
                }
                sent += n as u64;
            }
            Err(_) => return false,
        }
    }
    let _ = sock.shutdown().await;
    sent == size
}
