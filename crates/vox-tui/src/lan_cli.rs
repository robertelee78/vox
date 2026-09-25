//! `vox lan helper` and `vox lan up` — **the family LAN** on a real interface (PRD-001 R28,
//! ADR-013 §"The family LAN").
//!
//! ## Why a helper, and why it is this small
//! A macOS `utun` interface can only be created, addressed and routed by root. Everything
//! else the LAN does — opening the room, unlocking the identity, talking to peers, deciding
//! who is trusted — must not run as root, because it reads secrets and talks to the
//! network. So root's part is its own process, `sudo vox lan helper`, and it does exactly
//! four things per request:
//!
//! 1. checks the request comes from the person who started it (`getpeereid`);
//! 2. checks the addresses are a LAN's — a host in `100.64.0.0/10` and one in `fd00::/8`,
//!    so it can never be used to route anywhere else;
//! 3. creates a `utun`, gives it the two addresses and routes the room's /24 and /64 to it;
//! 4. hands the interface's file descriptor to `vox lan up` over the socket
//!    (`SCM_RIGHTS`) and closes its own copy.
//!
//! It never opens a profile, never unlocks anything and never touches the network. And
//! because it keeps nothing, **the interface lives exactly as long as `vox lan up`**: the
//! kernel destroys a `utun` — its addresses and its routes with it — when the last
//! descriptor closes, whether `vox lan up` stopped cleanly or crashed.
//!
//! The alternative the task named — one `sudo vox lan up` that drops privileges after
//! creating the device — was rejected on one concrete point: macOS keeps root's
//! supplementary groups (`admin`, `kmem`, `wheel`, …) across `setuid` unless
//! `setgroups` is called, and no safe binding offers `setgroups` on Apple targets. A node
//! still holding `kmem` is not a node that dropped privileges. The helper model has no
//! privileges to drop.
//!
//! ## What `vox lan up` does
//! Opens the room as `vox up <room>` does, computes the room's plan
//! ([`vox_core::lan::plan::LanPlan`]) to learn this node's two addresses, asks the helper
//! for an interface holding them, and runs the LAN engine on it until interrupted.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::app::AppError;

/// Where the helper listens unless told otherwise: in a root-owned directory, so nobody
/// else can put a socket there first.
pub const DEFAULT_HELPER_SOCKET: &str = "/var/run/vox-lan.sock";

/// What `vox lan up` asks the helper for: an interface holding these addresses, with the
/// room's /24 and /64 routed to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceRequest {
    /// This node's IPv4 address, or `None` past the plan's 254th member.
    pub v4: Option<Ipv4Addr>,
    /// This node's IPv6 address.
    pub v6: Ipv6Addr,
}

impl DeviceRequest {
    /// The request as its one line on the socket.
    #[must_use]
    pub fn line(&self) -> String {
        let v4 = self.v4.map_or_else(|| "-".to_owned(), |a| a.to_string());
        format!("up {v4} {}\n", self.v6)
    }

    /// Read and **validate** a request line: the helper's only input from a less
    /// privileged process, so it accepts LAN addresses and nothing else.
    ///
    /// # Errors
    /// A sentence saying what is wrong with it.
    pub fn parse(line: &str) -> Result<Self, String> {
        let mut words = line.split_whitespace();
        let (Some("up"), Some(v4), Some(v6), None) =
            (words.next(), words.next(), words.next(), words.next())
        else {
            return Err("expected `up <ipv4|-> <ipv6>`".into());
        };
        let v4 = if v4 == "-" {
            None
        } else {
            let a: Ipv4Addr = v4
                .parse()
                .map_err(|_| format!("{v4:?} is not an IPv4 address"))?;
            let o = a.octets();
            if o[0] != 100 || !(64..128).contains(&o[1]) || o[3] == 0 || o[3] == 255 {
                return Err(format!("{a} is not a LAN host in 100.64.0.0/10"));
            }
            Some(a)
        };
        let v6: Ipv6Addr = v6
            .parse()
            .map_err(|_| format!("{v6:?} is not an IPv6 address"))?;
        if v6.octets()[0] != 0xfd {
            return Err(format!("{v6} is not in fd00::/8"));
        }
        Ok(Self { v4, v6 })
    }

    fn subnet_v4(&self) -> Option<String> {
        self.v4.map(|a| {
            let o = a.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        })
    }

    fn prefix_v6(&self) -> String {
        let mut o = self.v6.octets();
        o[8..].fill(0);
        format!("{}/64", Ipv6Addr::from(o))
    }
}

/// Whether a helper is answering on `socket`.
#[must_use]
pub fn helper_reachable(socket: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket).is_ok()
}

/// What `vox lan up` says when there is no helper to ask: how to start one.
#[must_use]
pub fn no_helper(socket: &Path) -> String {
    let flag = if socket == Path::new(DEFAULT_HELPER_SOCKET) {
        String::new()
    } else {
        format!(" --socket {}", socket.display())
    };
    format!(
        "no LAN helper is answering on {}. Creating a network interface needs root, and \
         only the helper has it: start it in another terminal with\n\n    sudo vox lan helper{flag}\n\n\
         then run `vox lan up` again (as yourself, not with sudo).",
        socket.display()
    )
}

#[cfg(target_os = "macos")]
pub use mac::{run_helper, up};

#[cfg(not(target_os = "macos"))]
/// The helper. Built for macOS only so far.
///
/// # Errors
/// Always, on this platform.
pub fn run_helper(_socket: &Path) -> Result<(), AppError> {
    Err(AppError::Usage(NOT_HERE.into()))
}

#[cfg(not(target_os = "macos"))]
/// `vox lan up`. Built for macOS only so far.
///
/// # Errors
/// Always, on this platform.
pub async fn up(
    _node: &vox_core::node::actor::NodeHandle,
    _channel_id: vox_core::hash::Digest32,
    _socket: std::path::PathBuf,
    _stats_file: Option<std::path::PathBuf>,
) -> Result<(), AppError> {
    Err(AppError::Usage(NOT_HERE.into()))
}

#[cfg(not(target_os = "macos"))]
const NOT_HERE: &str = "the family LAN is built for macOS only so far: Linux's /dev/net/tun \
     needs an ioctl no safe binding offers, and Vox writes no `unsafe` (ADR-013 §\"The family LAN\")";

#[cfg(target_os = "macos")]
mod mac {
    use std::io::{self, BufRead as _, IoSlice, IoSliceMut, Write as _};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Duration;

    use nix::sys::socket::{
        connect, getsockopt, socket, sockopt, AddressFamily, SockFlag, SockProtocol, SockType,
        SysControlAddr,
    };
    use rustix::net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags,
    };
    use tokio::io::unix::AsyncFd;
    use vox_core::hash::Digest32;
    use vox_core::lan::plan::LanPlan;
    use vox_core::lan::{Lan, Tun, LAN_MTU};
    use vox_core::node::actor::NodeHandle;
    use vox_core::node::link::b32_encode;

    use super::{AppError, DeviceRequest};

    const UTUN_CONTROL: &str = "com.apple.net.utun_control";

    /// `AF_INET` and `AF_INET6` as a `utun` frames them: a 4-byte big-endian family
    /// ahead of every packet.
    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 30;

    fn create_utun() -> io::Result<(OwnedFd, String)> {
        let fd = socket(
            AddressFamily::System,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::KextControl,
        )?;
        use std::os::fd::AsRawFd as _;
        // Unit 0: the kernel picks the next free `utunN`.
        let addr = SysControlAddr::from_name(fd.as_raw_fd(), UTUN_CONTROL, 0)?;
        connect(fd.as_raw_fd(), &addr)?;
        let name = getsockopt(&fd, sockopt::UtunIfname)?
            .into_string()
            .map_err(|_| io::Error::other("the kernel named the interface in non-UTF-8"))?;
        Ok((fd, name))
    }

    /// Run one configuration command, returning it as it would be typed.
    fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
        let shown = format!("{cmd} {}", args.join(" "));
        let out = Command::new(cmd)
            .args(args)
            .output()
            .map_err(|e| format!("{shown}: {e}"))?;
        if out.status.success() {
            Ok(shown)
        } else {
            Err(format!(
                "{shown}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    /// Route `net` to `name`, or — if another interface already has the route, which on
    /// one machine means another LAN of the same room — scope the route to this interface,
    /// so a socket bound to it still reaches the LAN.
    fn route(family: &str, net: &str, name: &str) -> Result<String, String> {
        match run(
            "/sbin/route",
            &["-q", "-n", "add", family, net, "-interface", name],
        ) {
            Ok(s) => Ok(s),
            Err(e) if e.contains("File exists") => run(
                "/sbin/route",
                &[
                    "-q",
                    "-n",
                    "add",
                    family,
                    net,
                    "-interface",
                    name,
                    "-ifscope",
                    name,
                ],
            ),
            Err(e) => Err(e),
        }
    }

    fn configure(name: &str, req: &DeviceRequest) -> Result<Vec<String>, String> {
        let mut done = Vec::new();
        let mtu = LAN_MTU.to_string();
        if let (Some(v4), Some(net)) = (req.v4, req.subnet_v4()) {
            let host = format!("{v4}/24");
            let v4s = v4.to_string();
            done.push(run("/sbin/ifconfig", &[name, "inet", &host, &v4s, "up"])?);
            done.push(route("-inet", &net, name)?);
        }
        let v6 = format!("{}/64", req.v6);
        done.push(run("/sbin/ifconfig", &[name, "inet6", &v6, "alias"])?);
        done.push(run("/sbin/ifconfig", &[name, "mtu", &mtu, "up"])?);
        done.push(route("-inet6", &req.prefix_v6(), name)?);
        Ok(done)
    }

    fn serve_one(
        stream: &std::os::unix::net::UnixStream,
        owner: nix::unistd::Uid,
    ) -> Result<String, String> {
        let (uid, _) = nix::unistd::getpeereid(stream).map_err(|e| format!("getpeereid: {e}"))?;
        if uid != owner {
            return Err(format!(
                "uid {uid} asked, and this helper serves only uid {owner}, who started it"
            ));
        }
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        let mut line = String::new();
        std::io::BufReader::new(stream)
            .read_line(&mut line)
            .map_err(|e| format!("reading the request: {e}"))?;
        let req = DeviceRequest::parse(&line)?;
        let (fd, name) = create_utun().map_err(|e| format!("creating a utun: {e}"))?;
        // On any failure from here, dropping `fd` destroys the half-made interface.
        let done = configure(&name, &req)?;
        let reply = format!("ok {name}\n");
        let fds = [fd.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
            return Err("no room for the descriptor in the control message".into());
        }
        rustix::net::sendmsg(
            stream,
            &[IoSlice::new(reply.as_bytes())],
            &mut control,
            SendFlags::empty(),
        )
        .map_err(|e| format!("handing over {name}: {e}"))?;
        Ok(format!("{name} for uid {uid}: {}", done.join("; ")))
    }

    /// `sudo vox lan helper`: serve interface requests from the person who ran `sudo`
    /// until interrupted.
    ///
    /// # Errors
    /// If it is not root, cannot tell who ran `sudo`, or cannot listen.
    pub fn run_helper(socket: &Path) -> Result<(), AppError> {
        if !nix::unistd::geteuid().is_root() {
            return Err(AppError::Usage(
                "the helper creates network interfaces, which needs root: `sudo vox lan helper`"
                    .into(),
            ));
        }
        let id = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u32>().ok());
        let (Some(uid), Some(gid)) = (id("SUDO_UID"), id("SUDO_GID")) else {
            return Err(AppError::Usage(
                "start the helper with sudo, so it knows whom to serve: `sudo vox lan helper`"
                    .into(),
            ));
        };
        let (owner, group) = (
            nix::unistd::Uid::from_raw(uid),
            nix::unistd::Gid::from_raw(gid),
        );
        // A stale socket from a helper that did not exit cleanly is replaced; anything
        // else at that path is left alone.
        if let Ok(meta) = std::fs::symlink_metadata(socket) {
            if meta.file_type().is_socket() {
                std::fs::remove_file(socket)?;
            } else {
                return Err(AppError::Usage(format!(
                    "{} exists and is not a socket; not touching it",
                    socket.display()
                )));
            }
        }
        let listener = std::os::unix::net::UnixListener::bind(socket)?;
        nix::unistd::chown(socket, Some(owner), Some(group)).map_err(|e| AppError::Io(e.into()))?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
        println!(
            "vox lan helper: serving uid {uid} on {} — Ctrl-C to stop (running LANs keep their interfaces)",
            socket.display()
        );
        let path = socket.to_path_buf();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let result = rt.block_on(async move {
            listener.set_nonblocking(true)?;
            let listener = tokio::net::UnixListener::from_std(listener)?;
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    a = listener.accept() => {
                        let (stream, _) = a?;
                        let stream = stream.into_std()?;
                        stream.set_nonblocking(false)?;
                        let said = tokio::task::spawn_blocking(move || {
                            let r = serve_one(&stream, owner);
                            if let Err(e) = &r {
                                let _ = (&stream).write_all(format!("err {e}\n").as_bytes());
                            }
                            r
                        })
                        .await
                        .map_err(io::Error::other)?;
                        match said {
                            Ok(s) => println!("vox lan helper: {s}"),
                            Err(e) => println!("vox lan helper: refused: {e}"),
                        }
                    }
                }
            }
            Ok::<(), io::Error>(())
        });
        let _ = std::fs::remove_file(&path);
        println!("vox lan helper: stopped");
        result.map_err(AppError::Io)
    }

    fn request_device(socket: &Path, req: &DeviceRequest) -> Result<(OwnedFd, String), String> {
        let mut s = std::os::unix::net::UnixStream::connect(socket)
            .map_err(|_| super::no_helper(socket))?;
        s.set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| e.to_string())?;
        s.write_all(req.line().as_bytes())
            .map_err(|e| format!("asking the helper: {e}"))?;
        let mut buf = [0u8; 1024];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let got = rustix::net::recvmsg(
            &s,
            &mut [IoSliceMut::new(&mut buf)],
            &mut control,
            RecvFlags::empty(),
        )
        .map_err(|e| format!("reading the helper's answer: {e}"))?;
        let said = String::from_utf8_lossy(&buf[..got.bytes]).trim().to_owned();
        let mut fd = None;
        for msg in control.drain() {
            if let RecvAncillaryMessage::ScmRights(mut fds) = msg {
                fd = fds.next();
            }
        }
        match (said.strip_prefix("ok "), fd) {
            (Some(name), Some(fd)) => Ok((fd, name.to_owned())),
            _ => Err(format!(
                "the helper did not make the interface: {}",
                said.strip_prefix("err ").unwrap_or(&said)
            )),
        }
    }

    /// A `utun` interface, from the helper.
    struct Utun {
        fd: AsyncFd<OwnedFd>,
    }

    impl Tun for Utun {
        async fn recv(&self) -> Option<Vec<u8>> {
            let mut buf = vec![0u8; 4 + 65_535];
            loop {
                let mut ready = self.fd.readable().await.ok()?;
                match ready.try_io(|fd| {
                    rustix::io::read(fd.get_ref(), &mut buf[..]).map_err(io::Error::from)
                }) {
                    Ok(Ok(0)) => return None,
                    Ok(Ok(n)) if n > 4 => return Some(buf[4..n].to_vec()),
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                    Ok(Err(_)) => return None,
                    Err(_would_block) => {}
                }
            }
        }

        fn send(&self, packet: &[u8]) -> bool {
            let family = match packet.first().map(|b| b >> 4) {
                Some(4) => AF_INET,
                Some(6) => AF_INET6,
                _ => return false,
            };
            let mut framed = Vec::with_capacity(4 + packet.len());
            framed.extend_from_slice(&family.to_be_bytes());
            framed.extend_from_slice(packet);
            rustix::io::write(self.fd.get_ref(), &framed).is_ok()
        }
    }

    fn members(node: &NodeHandle, channel_id: &Digest32) -> Vec<Digest32> {
        node.view()
            .open_channels
            .iter()
            .find(|c| c.channel_id == *channel_id)
            .map(|c| c.members.clone())
            .unwrap_or_default()
    }

    fn stats_json(name: &str, me: &Digest32, lan: &Lan<Utun>) -> serde_json::Value {
        let plan = lan.plan();
        let s = lan.stats();
        let addrs = |m: &Digest32| {
            plan.of(m).map(|a| {
                serde_json::json!({
                    "v4": a.v4.map(|v| v.to_string()),
                    "v6": a.v6.to_string(),
                })
            })
        };
        let members: serde_json::Map<String, serde_json::Value> = plan
            .members
            .keys()
            .map(|m| (b32_encode(m), addrs(m).unwrap_or(serde_json::Value::Null)))
            .collect();
        serde_json::json!({
            "interface": name,
            "me": b32_encode(me),
            "addresses": addrs(me),
            "subnet_v4": format!("{}/24", plan.subnet_v4),
            "prefix_v6": format!("{}/64", plan.prefix_v6),
            "members": members,
            "links": s.links.iter().map(b32_encode).collect::<Vec<_>>(),
            "from_os": s.from_os,
            "to_peers": s.to_peers,
            "floods": s.floods,
            "flood_copies": s.flood_copies,
            "from_peers": s.from_peers,
            "to_os": s.to_os,
            "looped": s.looped,
            "off_lan": s.off_lan,
            "no_route": s.no_route,
            "spoofed": s.spoofed,
            "not_for_me": s.not_for_me,
            "rate_capped": s.rate_capped,
            "device_full": s.device_full,
        })
    }

    fn write_stats(path: &Path, v: &serde_json::Value) {
        // Written whole and renamed, so a reader never sees half a file.
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, v.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }

    /// Bring this node onto `channel_id`'s LAN through the helper on `socket`, and run it
    /// until interrupted. With `stats_file`, the plan, the links and the counters are
    /// written there as JSON twice a second.
    ///
    /// # Errors
    /// If the node has no identity, the helper refuses, or the LAN cannot start.
    pub async fn up(
        node: &NodeHandle,
        channel_id: Digest32,
        socket: PathBuf,
        stats_file: Option<PathBuf>,
    ) -> Result<(), AppError> {
        let me = node
            .view()
            .identity
            .map(|i| i.fingerprint)
            .ok_or_else(|| AppError::Usage("this profile has no identity".into()))?;
        let plan = LanPlan::new(channel_id, &members(node, &channel_id));
        let mine = *plan
            .of(&me)
            .ok_or_else(|| AppError::Usage("this node is not a member of that room".into()))?;
        let req = DeviceRequest {
            v4: mine.v4,
            v6: mine.v6,
        };
        let (fd, name) = tokio::task::spawn_blocking(move || request_device(&socket, &req))
            .await
            .map_err(|e| AppError::Usage(e.to_string()))?
            .map_err(AppError::Usage)?;
        rustix::io::ioctl_fionbio(&fd, true).map_err(io::Error::from)?;
        let utun = Utun {
            fd: AsyncFd::new(fd)?,
        };
        let lan = Lan::start(node, channel_id, utun)?;
        let v4 = mine.v4.map_or_else(
            || "no IPv4 (past 254 members)".to_owned(),
            |a| a.to_string(),
        );
        println!(
            "vox lan up on {name} — this node is {v4} and {}; the room's LAN is {}/24 and {}/64",
            mine.v6, plan.subnet_v4, plan.prefix_v6
        );
        println!("Ctrl-C to stop; the interface goes with it");
        let mut linked: Vec<Digest32> = Vec::new();
        let mut moved_said = false;
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = tick.tick() => {
                    let s = lan.stats();
                    for m in s.links.iter().filter(|m| !linked.contains(m)) {
                        println!("vox lan: linked with {}", b32_encode(m));
                    }
                    for m in linked.iter().filter(|m| !s.links.contains(m)) {
                        println!("vox lan: link to {} ended", b32_encode(m));
                    }
                    linked = s.links;
                    let now = lan.plan().of(&me).copied();
                    if now != Some(mine) && !moved_said {
                        moved_said = true;
                        println!(
                            "vox lan: a member joined whose address took precedence over this \
                             node's; restart `vox lan up` to take the new one"
                        );
                    }
                    if let Some(p) = &stats_file {
                        write_stats(p, &stats_json(&name, &me, &lan));
                    }
                }
            }
        }
        drop(lan);
        println!("vox lan: down");
        Ok(())
    }
}
