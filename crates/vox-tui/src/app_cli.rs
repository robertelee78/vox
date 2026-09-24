//! `vox app` — the app API from a shell (ADR-022 decision 7), over a running node.
//!
//! Two verbs, the shape of `nc`:
//!
//! - `vox app listen <room> <label>` waits for one app stream speaking `label`, accepts
//!   it, and pipes it to stdin and stdout;
//! - `vox app open <room> <peer> <label>…` opens one and does the same.
//!
//! They are thin clients of IPC protocol 6 (`vox_core::node::appipc`): the program a
//! person would write against the app API, runnable from a script, which is what the
//! proofs drive. Like `vox room`, they attach to the node already running this profile
//! and hold no secret of their own.
//!
//! With `--datagrams` the stream also carries a datagram flow, and the pipe changes
//! shape: each **line** of stdin is sent as one datagram, and each datagram received is
//! printed as one line. Stream bytes still pass through, but a line-oriented pipe cannot
//! carry both unambiguously, so in that mode stdin is datagrams only.

use std::io::{BufRead as _, Read as _, Write as _};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use vox_core::hash::Digest32;
use vox_core::node::appipc::{self, read_splice, write_splice, SpliceFrame};
use vox_core::node::ipc::{Frame, IpcClient, Request};
use vox_core::node::link::b32_encode;
use vox_core::node::paths::Paths;

use crate::app::AppError;
use crate::tunnel_cli::resolve_prefix;

async fn client(paths: &Paths) -> Result<IpcClient, AppError> {
    let sock = paths.socket_file();
    IpcClient::open(&sock).await.map_err(|_| {
        AppError::Usage(format!(
            "no node answers at {} — start one with `vox daemon` (or `vox tui`)",
            sock.display()
        ))
    })
}

/// Resolve a room prefix against the rooms the node holds.
async fn room(c: &mut IpcClient, prefix: &str) -> Result<Digest32, AppError> {
    match c.request(&Request::Rooms).await {
        Ok(Frame::Rooms { rooms }) => {
            let ids: Vec<Digest32> = rooms.iter().map(|(id, _, _)| *id).collect();
            resolve_prefix(prefix, &ids)
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        other => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
    }
}

/// Resolve a member prefix against the room's roster.
async fn member(c: &mut IpcClient, room: Digest32, prefix: &str) -> Result<Digest32, AppError> {
    match c.request(&Request::Roster { channel_id: room }).await {
        Ok(Frame::Members { members }) => resolve_prefix(prefix, &members),
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        other => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
    }
}

/// `vox app listen` — accept one app stream and pipe it.
pub async fn listen(paths: &Paths, room_prefix: &str, label: &str) -> Result<(), AppError> {
    let mut c = client(paths).await?;
    let room_id = room(&mut c, room_prefix).await?;
    drop(c);
    let sock = paths.socket_file();
    let mut listener = appipc::listen(&sock, Some(room_id), label)
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?;
    eprintln!("vox app: listening for {label} in {}", short(&room_id));
    let incoming = listener
        .next()
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?
        .ok_or_else(|| AppError::Usage("the node stopped".into()))?;
    let (stream, info) = appipc::accept(&sock, incoming.id)
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?;
    // One stream, like `nc -l`: stop listening once it is taken.
    drop(listener);
    eprintln!(
        "vox app: {} from {}{}",
        info.label,
        b32_encode(&info.peer),
        if info.datagrams { " (datagrams)" } else { "" }
    );
    pipe(stream, info.datagrams).await
}

/// `vox app open` — open one app stream and pipe it.
pub async fn open(
    paths: &Paths,
    room_prefix: &str,
    peer_prefix: &str,
    labels: Vec<String>,
    datagrams: bool,
) -> Result<(), AppError> {
    let mut c = client(paths).await?;
    let room_id = room(&mut c, room_prefix).await?;
    let peer = member(&mut c, room_id, peer_prefix).await?;
    drop(c);
    let (stream, info) = appipc::open(&paths.socket_file(), room_id, peer, labels, datagrams)
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?;
    eprintln!("vox app: {} to {}", info.label, b32_encode(&info.peer));
    pipe(stream, info.datagrams).await
}

fn short(d: &Digest32) -> String {
    b32_encode(d).chars().take(12).collect()
}

/// Carry the splice to stdin and stdout until the stream is over, or fails.
///
/// With datagrams the connection is framed and the node closes it when both halves have
/// ended or the stream fails, so the end of input is the whole answer. Without them it is
/// raw bytes, and the end of input only means the peer finished sending: the command then
/// keeps sending stdin until it ends, and stops early only if the node closes the
/// connection outright — which is what it does when the stream fails, including when trust
/// is withdrawn. A zero-byte write tells the two apart: it succeeds on a half-closed
/// connection and fails on a closed one.
async fn pipe(stream: tokio::net::UnixStream, datagrams: bool) -> Result<(), AppError> {
    let (mut r, mut w) = stream.into_split();
    let mut out = std::io::stdout().lock();
    // stdin is read on a plain thread: a blocking read is what a terminal or a pipe
    // gives, and the runtime is shut down in the background so it cannot hold us up.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        if datagrams {
            let mut line = String::new();
            while matches!(stdin.read_line(&mut line), Ok(n) if n > 0) {
                let d = line.trim_end_matches(['\r', '\n']).as_bytes().to_vec();
                line.clear();
                if tx.blocking_send(d).is_err() {
                    return;
                }
            }
        } else {
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(n) = stdin.read(&mut buf) {
                if n == 0 || tx.blocking_send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        }
    });
    if datagrams {
        tokio::spawn(async move {
            while let Some(d) = rx.recv().await {
                if write_splice(&mut w, &SpliceFrame::Datagram(d))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            let _ = write_splice(&mut w, &SpliceFrame::Fin).await;
        });
        while let Some(frame) = read_splice(&mut r)
            .await
            .map_err(|e| AppError::Usage(e.to_string()))?
        {
            match frame {
                SpliceFrame::Data(d) => {
                    out.write_all(&d)?;
                    out.flush()?;
                }
                SpliceFrame::Datagram(mut d) => {
                    d.push(b'\n');
                    out.write_all(&d)?;
                    out.flush()?;
                }
                // The peer finished its half; datagrams may still come.
                SpliceFrame::Fin => {}
            }
        }
        out.flush()?;
        eprintln!("vox app: the stream ended");
        return Ok(());
    }
    let mut buf = vec![0u8; 64 * 1024];
    let (mut net_done, mut stdin_done, mut cut) = (false, false, false);
    let mut probe = tokio::time::interval(std::time::Duration::from_millis(100));
    while !(net_done && stdin_done) {
        tokio::select! {
            n = r.read(&mut buf), if !net_done => {
                let n = n?;
                if n == 0 {
                    net_done = true;
                    out.flush()?;
                } else {
                    // Flushed per chunk: stdout is line-buffered and these are bytes, so
                    // an unflushed tail would sit here while the peer waits for it.
                    out.write_all(&buf[..n])?;
                    out.flush()?;
                }
            }
            chunk = rx.recv(), if !stdin_done => match chunk {
                Some(c) => {
                    if w.write_all(&c).await.is_err() {
                        cut = true;
                        break;
                    }
                }
                None => {
                    stdin_done = true;
                    let _ = w.shutdown().await;
                }
            },
            _ = probe.tick(), if net_done => {
                if w.try_write(&[]).is_err() {
                    cut = true;
                    break;
                }
            }
        }
    }
    out.flush()?;
    if cut {
        return Err(AppError::Usage(
            "the stream was closed before it ended — trust was withdrawn on one side, or              the connection failed"
                .into(),
        ));
    }
    eprintln!("vox app: the stream ended");
    Ok(())
}
