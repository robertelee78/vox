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
pub const DEFAULT_HELPER_SOCKET: &str = vox_core::node::lan_request::DEFAULT_HELPER_SOCKET;

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

    /// Only the macOS helper configures an interface from it.
    #[cfg(target_os = "macos")]
    fn subnet_v4(&self) -> Option<String> {
        self.v4.map(|a| {
            let o = a.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        })
    }

    /// An address on the room's IPv4 LAN other than this node's, for the helper to look up
    /// the route it added: the LAN's `.1`, or `.2` when this node is `.1`.
    #[cfg(target_os = "macos")]
    fn other_v4(&self) -> Option<Ipv4Addr> {
        self.v4.map(|a| {
            let o = a.octets();
            Ipv4Addr::new(o[0], o[1], o[2], if o[3] == 1 { 2 } else { 1 })
        })
    }

    /// [`Self::other_v4`] for the room's IPv6 prefix: `::1` in it, or `::2`.
    #[cfg(target_os = "macos")]
    fn other_v6(&self) -> Ipv6Addr {
        let mut o = self.v6.octets();
        let last = if o[8..15].iter().all(|b| *b == 0) && o[15] == 1 {
            2
        } else {
            1
        };
        o[8..].fill(0);
        o[15] = last;
        Ipv6Addr::from(o)
    }

    /// Only the macOS helper configures an interface from it.
    #[cfg(target_os = "macos")]
    fn prefix_v6(&self) -> String {
        let mut o = self.v6.octets();
        o[8..].fill(0);
        format!("{}/64", Ipv6Addr::from(o))
    }
}

/// What `vox lan up` sends to ask whether a helper is there, before the node does any work.
pub const HELLO: &str = "hello";

/// The first words of a helper's answer to [`HELLO`]; its protocol version follows.
pub const HELPER_SAYS: &str = "vox lan helper";

/// The protocol this helper speaks: [`HELPER_SAYS`] `1`.
pub const HELPER_PROTOCOL: u32 = 1;

/// How long a helper has to answer [`HELLO`]: it answers at once, so a socket that says nothing
/// in this time is not one.
const HELLO_WITHIN: std::time::Duration = std::time::Duration::from_secs(2);

/// Whether a helper is answering on `socket`: it must answer [`HELLO`] as a helper. `Err` says
/// what to do: [`no_helper`] when nothing listens there, and the socket named when something that
/// is not a helper does.
///
/// A connection alone was the check, so anything listening on that path passed it, and `vox lan
/// up` then waited 30 s for a device that never came (#75's review). Asking for the helper's own
/// words refuses a wrong socket at once.
///
/// # Errors
/// As above.
pub fn helper_answers(socket: &Path) -> Result<(), String> {
    use std::io::{BufRead as _, Write as _};
    let Ok(mut s) = std::os::unix::net::UnixStream::connect(socket) else {
        return Err(no_helper(socket));
    };
    let not_one = |why: String| {
        format!(
            "{} answers, but not as a vox LAN helper ({why}). Is another program using that \
             path? Start the helper on a path of its own with\n\n    sudo vox lan helper \
             --socket <path>\n\nand give `vox lan up` the same --helper-socket.",
            socket.display()
        )
    };
    let _ = s.set_read_timeout(Some(HELLO_WITHIN));
    let _ = s.set_write_timeout(Some(HELLO_WITHIN));
    if let Err(e) = s.write_all(format!("{HELLO}\n").as_bytes()) {
        return Err(not_one(format!("it would not take a line: {e}")));
    }
    let mut line = String::new();
    match std::io::BufReader::new(&s).read_line(&mut line) {
        Ok(_) if line.starts_with(HELPER_SAYS) => {
            let version = line[HELPER_SAYS.len()..].trim();
            if version == HELPER_PROTOCOL.to_string() {
                Ok(())
            } else {
                Err(format!(
                    "the LAN helper on {} speaks protocol {version:?}, and this vox speaks \
                     {HELPER_PROTOCOL}: start the helper from this vox (sudo {} lan helper)",
                    socket.display(),
                    std::env::current_exe()
                        .map_or_else(|_| "vox".to_owned(), |p| p.display().to_string())
                ))
            }
        }
        Ok(0) => Err(not_one("it closed without a word".into())),
        Ok(_) => Err(not_one(format!("it said {:?}", line.trim()))),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Err(not_one(format!(
                "it said nothing within {} s",
                HELLO_WITHIN.as_secs()
            )))
        }
        Err(e) => Err(not_one(format!("reading its answer: {e}"))),
    }
}

/// What `vox lan up` says when there is no helper to ask: how to start one. A `vox` inside Vox.app
/// points at the app's helper, which replaces `sudo vox lan helper` on a Mac (ADR-014 M-10).
#[must_use]
pub fn no_helper(socket: &Path) -> String {
    let flag = if socket == Path::new(DEFAULT_HELPER_SOCKET) {
        if let Some(app) = vox_app() {
            return format!(
                "no LAN helper is answering on {}. On this Mac the helper is Vox.app's: open Vox \
                 ({}), choose the room, and turn on \"On this room's LAN\" under FAMILY LAN \
                 beside its timeline; then open System Settings › General › Login Items & \
                 Extensions and, under \"Allow in the Background\", turn on Vox. Then run `vox lan \
                 up` again (as yourself, not with sudo).",
                socket.display(),
                app.display()
            );
        }
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

/// The Vox.app this `vox` is, when it runs as the bundle's own `Contents/Helpers/vox`.
fn vox_app() -> Option<std::path::PathBuf> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .ok()?;
    let helpers = exe.parent()?;
    let contents = helpers.parent()?;
    let app = contents.parent()?;
    (helpers.file_name()? == "Helpers"
        && contents.file_name()? == "Contents"
        && app.extension()? == "app")
        .then(|| app.to_path_buf())
}

#[cfg(target_os = "macos")]
pub use mac::{run_helper, up};

#[cfg(not(target_os = "macos"))]
/// The helper. Built for macOS only so far.
///
/// # Errors
/// Always, on this platform.
pub fn run_helper(_socket: &Path, _serve_bundle_owner: bool) -> Result<(), AppError> {
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
    _allow: std::collections::BTreeSet<u16>,
    _say: &(dyn Fn(String) + Send + Sync),
    _stop: impl std::future::Future<Output = ()>,
) -> Result<(), AppError> {
    Err(AppError::Usage(NOT_HERE.into()))
}

#[cfg(not(target_os = "macos"))]
const NOT_HERE: &str = "the family LAN is built for macOS only so far: Linux's /dev/net/tun \
     needs an ioctl no safe binding offers, and Vox writes no `unsafe`";

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

    /// Run `/sbin/route` with `args`, returning it as typed and what it printed. macOS's `route
    /// add` can exit 0 having added nothing (it prints `File exists` and carries on), so its
    /// exit status alone says little: callers look up what they added ([`routed`]).
    fn route_cmd(args: &[&str]) -> Result<(String, String), String> {
        let shown = format!("/sbin/route {}", args.join(" "));
        let out = Command::new("/sbin/route")
            .args(args)
            .output()
            .map_err(|e| format!("{shown}: {e}"))?;
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .trim()
        .to_owned();
        if out.status.success() || said.contains("File exists") {
            Ok((shown, said))
        } else {
            Err(format!("{shown}: {said}"))
        }
    }

    /// Whether `addr`, looked up scoped to `name`, goes out of `name` by the route to `net`
    /// itself: `Err` with what the lookup said when not. The destination is checked too: an
    /// interface can carry a scoped default route (macOS gives its own `utun`s one for IPv6),
    /// which would answer for any address.
    fn routed(family: &str, addr: &str, net: &str, name: &str) -> Result<(), String> {
        let base = net.split('/').next().unwrap_or(net);
        let out = Command::new("/sbin/route")
            .args(["-n", "get", family, "-ifscope", name, addr])
            .output()
            .map_err(|e| format!("/sbin/route -n get: {e}"))?;
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let field = |k: &str| {
            said.lines()
                .find_map(|l| l.trim().strip_prefix(k).map(|v| v.trim().to_owned()))
        };
        if field("interface:").as_deref() == Some(name)
            && field("destination:").as_deref() == Some(base)
        {
            Ok(())
        } else {
            Err(format!(
                "/sbin/route -n get {family} -ifscope {name} {addr} said: {}",
                said.split_whitespace().collect::<Vec<_>>().join(" ")
            ))
        }
    }

    /// Route the room's `net` to `name`, and say what was done; an error if `name` cannot reach
    /// `other` (an address on that LAN) afterwards.
    ///
    /// **Scoped to the interface, always.** Two nodes on one machine each run their own LAN of
    /// the same room, each on its own `utun`, all with the same subnet. Only one unscoped route
    /// to a subnet can exist, so every interface after the first had none: a socket bound to it
    /// (`ping -b`, `IP_BOUND_IF`) was told "No route to host" (#75, the decider's run). A route
    /// scoped with `-ifscope` exists per interface, and a bound socket finds its own.
    ///
    /// **And unscoped when none is there yet**, so an application that binds nothing (a media
    /// player finding a server) reaches the LAN; with two LANs of one room on one machine that
    /// route is the first one's. A route add that fails is an error the helper reports, never
    /// silence: `route` is run without `-q`, and the scoped route is looked up after.
    fn route(family: &str, net: &str, other: &str, name: &str) -> Result<String, String> {
        let (shown, said) = route_cmd(&["-n", "add", family, net, "-interface", name])?;
        let unscoped = if said.contains("File exists") {
            format!("{shown}: another interface has it")
        } else {
            shown
        };
        let (scoped, _) = route_cmd(&[
            "-n",
            "add",
            family,
            net,
            "-interface",
            name,
            "-ifscope",
            name,
        ])?;
        routed(family, other, net, name).map_err(|why| {
            format!(
                "{scoped}: {name} has no route to {net} afterwards, so nothing bound to it would \
                 reach the LAN ({why})"
            )
        })?;
        Ok(format!("{unscoped}; {scoped}"))
    }

    fn configure(name: &str, req: &DeviceRequest) -> Result<Vec<String>, String> {
        let mut done = Vec::new();
        let mtu = LAN_MTU.to_string();
        if let (Some(v4), Some(net)) = (req.v4, req.subnet_v4()) {
            let host = format!("{v4}/24");
            let v4s = v4.to_string();
            done.push(run("/sbin/ifconfig", &[name, "inet", &host, &v4s, "up"])?);
            let other = req.other_v4().map(|a| a.to_string()).unwrap_or_default();
            done.push(route("-inet", &net, &other, name)?);
        }
        let v6 = format!("{}/64", req.v6);
        done.push(run("/sbin/ifconfig", &[name, "inet6", &v6, "alias"])?);
        done.push(run("/sbin/ifconfig", &[name, "mtu", &mtu, "up"])?);
        done.push(route(
            "-inet6",
            &req.prefix_v6(),
            &req.other_v6().to_string(),
            name,
        )?);
        Ok(done)
    }

    /// Serve one connection: `Ok(None)` for one that asked for no device.
    ///
    /// **`hello` is answered, and not logged.** `vox lan up` first asks whether a helper is
    /// there ([`super::helper_answers`]), before the node does any work; the helper answers
    /// with its name and protocol, and that is all. **A connection that closes unasked** is
    /// served silently too: by the time the helper takes it the client has gone, and macOS
    /// refuses `setsockopt` on such a socket with `EINVAL`, which the helper once logged as
    /// `refused: Invalid argument (os error 22)` (#75, the decider's run).
    fn serve_one(
        stream: &std::os::unix::net::UnixStream,
        owner: nix::unistd::Uid,
    ) -> Result<Option<String>, String> {
        let (uid, _) = nix::unistd::getpeereid(stream).map_err(|e| format!("getpeereid: {e}"))?;
        if uid != owner {
            return Err(format!(
                "uid {uid} asked, and this helper serves only uid {owner}"
            ));
        }
        match stream.set_read_timeout(Some(Duration::from_secs(5))) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(nix::libc::EINVAL) => return Ok(None),
            Err(e) => return Err(format!("setting the request's read timeout: {e}")),
        }
        let mut line = String::new();
        let got = std::io::BufReader::new(stream)
            .read_line(&mut line)
            .map_err(|e| format!("reading the request: {e}"))?;
        if got == 0 {
            return Ok(None);
        }
        if line.trim() == super::HELLO {
            let _ = std::io::Write::write_all(
                &mut &*stream,
                format!("{} {}\n", super::HELPER_SAYS, super::HELPER_PROTOCOL).as_bytes(),
            );
            return Ok(None);
        }
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
        // Keep our copy until `vox lan up` has taken its own, which it shows by closing
        // the connection. A descriptor whose only reference is a message in flight is,
        // to macOS's collector for such descriptors (run whenever any local socket is
        // freed, as this connection is next), unreachable: it flushes the socket's
        // receive side for good, and the interface is deaf to everything the machine
        // sends into it while still able to deliver out of it.
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("waiting for {name} to be taken: {e}"))?;
        let _ = std::io::Read::read(&mut &*stream, &mut [0u8; 1]);
        drop(fd);
        Ok(Some(format!("{name} for uid {uid}: {}", done.join("; "))))
    }

    /// `sudo vox lan helper`: serve interface requests from the person who ran `sudo`, or with
    /// `serve_bundle_owner` from the person who owns the Vox.app it is inside (ADR-014 M-10),
    /// until interrupted.
    ///
    /// # Errors
    /// If it is not root, cannot tell whom to serve, or cannot listen.
    pub fn run_helper(socket: &Path, serve_bundle_owner: bool) -> Result<(), AppError> {
        // Whom it serves is worked out first, so a refusal to run says it either way.
        let whom = if serve_bundle_owner {
            bundle_owner().map_err(AppError::Usage)?
        } else {
            let id = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u32>().ok());
            let (Some(uid), Some(gid)) = (id("SUDO_UID"), id("SUDO_GID")) else {
                return Err(AppError::Usage(
                    "start the helper with sudo, so it knows whom to serve: `sudo vox lan helper`"
                        .into(),
                ));
            };
            Owner {
                uid,
                gid,
                why: "who ran sudo".into(),
            }
        };
        if !nix::unistd::geteuid().is_root() {
            return Err(AppError::Usage(format!(
                "the helper creates network interfaces, which needs root: `sudo vox lan helper` \
                 (it would serve uid {}, {})",
                whom.uid, whom.why
            )));
        }
        let Owner { uid, gid, .. } = whom;
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
            // One Ctrl-C listener for the whole loop: one made per turn misses a SIGINT that
            // lands in the same turn as another arm (see `app::run_node`).
            let interrupted = tokio::signal::ctrl_c();
            tokio::pin!(interrupted);
            loop {
                tokio::select! {
                    _ = &mut interrupted => break,
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
                            Ok(Some(s)) => println!("vox lan helper: {s}"),
                            Ok(None) => {}
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

    /// Whom the helper serves, and why that person.
    struct Owner {
        uid: u32,
        gid: u32,
        why: String,
    }

    /// The person who owns the Vox.app this `vox` is inside (ADR-014 M-10): only they, or root,
    /// can change what this root helper runs. Refused, with why, for a Vox.app owned by root, a
    /// directory or file from the bundle down to this `vox` that is not theirs or that others
    /// may write, or a bundle whose signature is not valid or not by this `vox`'s Developer ID
    /// team.
    fn bundle_owner() -> Result<Owner, String> {
        use std::os::unix::fs::MetadataExt as _;
        let exe = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|e| format!("cannot find this vox: {e}"))?;
        let bundle = exe
            .ancestors()
            .find(|p| p.extension().is_some_and(|x| x == "app"))
            .ok_or_else(|| {
                format!(
                    "{} is not inside a Vox.app, so there is no owner to serve",
                    exe.display()
                )
            })?
            .to_path_buf();
        let meta = std::fs::metadata(&bundle).map_err(|e| format!("{}: {e}", bundle.display()))?;
        let (uid, gid) = (meta.uid(), meta.gid());
        if uid == 0 {
            return Err(format!(
                "{} is owned by root, so it has no person to serve; the helper serves the person \
                 who owns Vox.app",
                bundle.display()
            ));
        }
        // Everything from the bundle down to this `vox`: its owner's alone, written by no one else.
        let mut path = bundle.clone();
        let mut walk = vec![bundle.clone()];
        for part in exe
            .strip_prefix(&bundle)
            .map_err(|e| e.to_string())?
            .components()
        {
            path.push(part);
            walk.push(path.clone());
        }
        for p in &walk {
            let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
            if m.uid() != uid && m.uid() != 0 {
                return Err(format!(
                    "{} belongs to uid {}, not to Vox.app's owner uid {uid}; not serving",
                    p.display(),
                    m.uid()
                ));
            }
            if m.mode() & 0o022 != 0 {
                return Err(format!(
                    "{} can be written by others (mode {:o}), so what this helper runs could be \
                     changed by them; not serving",
                    p.display(),
                    m.mode() & 0o7777
                ));
            }
        }
        let bundle_team = signing_team(&bundle)?;
        let own_team = signing_team(&exe)?;
        if bundle_team != own_team {
            return Err(format!(
                "{} is signed by team {bundle_team}, and this vox by team {own_team}; not serving",
                bundle.display()
            ));
        }
        Ok(Owner {
            uid,
            gid,
            why: format!("who owns {}", bundle.display()),
        })
    }

    /// The Developer ID team that signed `path`, once its signature checks out
    /// (`codesign --verify --strict`). Refused for an ad hoc signature, which names no team.
    fn signing_team(path: &Path) -> Result<String, String> {
        let codesign = "/usr/bin/codesign";
        let verify = Command::new(codesign)
            .args(["--verify", "--strict"])
            .arg(path)
            .output()
            .map_err(|e| format!("cannot run {codesign}: {e}"))?;
        if !verify.status.success() {
            return Err(format!(
                "{}'s signature does not check out: {}",
                path.display(),
                String::from_utf8_lossy(&verify.stderr).trim()
            ));
        }
        let shown = Command::new(codesign)
            .args(["--display", "--verbose=2"])
            .arg(path)
            .output()
            .map_err(|e| format!("cannot run {codesign}: {e}"))?;
        // codesign says what it shows on stderr.
        let said = String::from_utf8_lossy(&shown.stderr);
        match said
            .lines()
            .find_map(|l| l.strip_prefix("TeamIdentifier="))
            .map(str::trim)
        {
            Some(team) if !team.is_empty() && team != "not set" => Ok(team.to_owned()),
            _ => Err(format!(
                "{} is not signed with a Developer ID (no team), so the helper will not serve it",
                path.display()
            )),
        }
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

    fn stats_json(
        name: &str,
        me: &Digest32,
        lan: &Lan<Utun>,
        allow: &std::collections::BTreeSet<u16>,
    ) -> serde_json::Value {
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
            "filtered": s.filtered,
            "allow": allow.iter().collect::<Vec<_>>(),
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
    /// until `stop`. With `stats_file`, the plan, the links and the counters are written there
    /// as JSON twice a second. Run by the daemon as the node (ADR-026 S-5): what it has to say
    /// goes to `say`, which carries it to the `vox lan up` that asked.
    ///
    /// # Errors
    /// If the node has no identity, the helper refuses, or the LAN cannot start.
    pub async fn up(
        node: &NodeHandle,
        channel_id: Digest32,
        socket: PathBuf,
        stats_file: Option<PathBuf>,
        allow: std::collections::BTreeSet<u16>,
        say: &(dyn Fn(String) + Send + Sync),
        stop: impl std::future::Future<Output = ()>,
    ) -> Result<(), AppError> {
        let me = node
            .view()
            .identity
            .map(|i| i.fingerprint)
            .ok_or_else(|| AppError::Usage("this node has no identity".into()))?;
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
        let lan = Lan::start(node, channel_id, utun, allow.clone())?;
        let v4 = mine.v4.map_or_else(
            || "no IPv4 (past 254 members)".to_owned(),
            |a| a.to_string(),
        );
        say(format!(
            "vox lan up on {name} — this node is {v4} and {}; the room's LAN is {}/24 and {}/64",
            mine.v6, plan.subnet_v4, plan.prefix_v6
        ));
        if allow.is_empty() {
            say(
                "nothing on this machine is reachable over the LAN (discovery still flows); \
                 `--allow <port>,…` opens ports"
                    .to_owned(),
            );
        } else {
            let ports: Vec<String> = allow.iter().map(u16::to_string).collect();
            say(format!(
                "reachable over the LAN: ports {}",
                ports.join(", ")
            ));
        }
        say("Ctrl-C to stop; the interface goes with it".to_owned());
        let mut linked: Vec<Digest32> = Vec::new();
        let mut moved_said = false;
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tokio::pin!(stop);
        loop {
            tokio::select! {
                () = &mut stop => break,
                _ = tick.tick() => {
                    let s = lan.stats();
                    for m in s.links.iter().filter(|m| !linked.contains(m)) {
                        say(format!("vox lan: linked with {}", b32_encode(m)));
                    }
                    for m in linked.iter().filter(|m| !s.links.contains(m)) {
                        say(format!("vox lan: link to {} ended", b32_encode(m)));
                    }
                    linked = s.links;
                    let now = lan.plan().of(&me).copied();
                    if now != Some(mine) && !moved_said {
                        moved_said = true;
                        say("vox lan: a member joined whose address took precedence over this \
                             node's; restart `vox lan up` to take the new one"
                            .to_owned());
                    }
                    if let Some(p) = &stats_file {
                        write_stats(p, &stats_json(&name, &me, &lan, &allow));
                    }
                }
            }
        }
        drop(lan);
        say("vox lan: down".to_owned());
        Ok(())
    }
}

// ---- `vox lan up` through the daemon (ADR-026 S-5) ------------------------------------------

use vox_core::node::lan_request::{LanRequest, LanSaid};

/// The daemon's side of `vox lan up` (ADR-026 S-5): it asks the root helper for the device as
/// this user, and runs the LAN as the node until the client's connection closes. The helper is
/// unchanged; the account socket never admits root (C-1).
pub struct LanUp;

impl vox_core::node::ipc::Extension for LanUp {
    fn claims(&self, body: &[u8]) -> bool {
        LanRequest::claims(body)
    }

    fn serve(
        &self,
        body: Vec<u8>,
        stream: tokio::net::UnixStream,
        handle: vox_core::node::actor::NodeHandle,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let (mut r, mut w) = stream.into_split();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            let writer = tokio::spawn(async move {
                while let Some(frame) = rx.recv().await {
                    if w.write_all(&frame).await.is_err() {
                        break;
                    }
                }
            });
            let Some(req) = LanRequest::parse(&body) else {
                let _ = tx.send(LanSaid::Failed("that is not a LAN request".into()).framed());
                drop(tx);
                let _ = writer.await;
                return;
            };
            let said = tx.clone();
            // **The daemon says it too** (R36): what a LAN said goes to its `vox lan up`, and to
            // the daemon's own log, so a LAN whose client is gone still left a trace of how far it
            // got (#75: a root run's `vox lan up` exited saying nothing, its LAN's interface made).
            let who = handle
                .view()
                .identity
                .map(|i| vox_core::node::link::b32_encode(&i.fingerprint)[..12].to_owned())
                .unwrap_or_default();
            let tag = who.clone();
            let say = move |line: String| {
                eprintln!("vox daemon: {tag}: {line}");
                let _ = said.send(LanSaid::Said(line).framed());
            };
            // The LAN lives exactly as long as the client's connection.
            let stop = async move {
                let mut b = [0u8; 1];
                while matches!(r.read(&mut b).await, Ok(n) if n > 0) {}
            };
            let out = up(
                &handle,
                req.channel_id,
                req.helper,
                req.stats_file,
                req.allow,
                &say,
                stop,
            )
            .await;
            match out {
                Ok(()) => eprintln!(
                    "vox daemon: {who}: a LAN stopped: its `vox lan up` closed its connection"
                ),
                Err(e) => {
                    eprintln!("vox daemon: {who}: a LAN could not run: {e}");
                    let _ = tx.send(LanSaid::Failed(e.to_string()).framed());
                }
            }
            drop(say);
            drop(tx);
            let _ = writer.await;
        })
    }
}

/// `vox lan up <room>`, a client of the daemon holding this node (ADR-026 S-5, L-7): it opens the
/// room if a passphrase is given and it is closed, asks the daemon to run the LAN, and prints what
/// the daemon says until it is stopped, or non-zero when the daemon goes.
///
/// # Errors
/// The node not held, the room not open, or the LAN not started, with why.
pub async fn up_held(
    paths: &vox_core::node::paths::Paths,
    args: &crate::cli::LanUpArgs,
    waiting: &crate::tunnel_cli::Waiting,
) -> Result<(), AppError> {
    if args.metrics.is_some() {
        eprintln!(
            "vox lan: --metrics is served by the vox daemon for every node: vox daemon --metrics \
             <addr>"
        );
    }
    let room = &args.room;
    let room_pp = match &room.passphrase_file {
        Some(f) => {
            let text = crate::tunnel_cli::passphrase_file_text(f)?;
            Some(text.lines().next().unwrap_or_default().to_owned())
        }
        None => None,
    };
    let mut held = crate::client::hold(
        paths,
        &room.profile,
        crate::client::Pass {
            flag: room.identity_passphrase.clone(),
            file: room.identity_passphrase_file.clone(),
        },
        false,
        Some(waiting),
    )
    .await?;
    let channel_id =
        crate::tunnel_cli::open_named_room(&mut held.client, &room.room, room_pp.as_deref())
            .await?;
    waiting.on("the daemon to bring the LAN up");
    let (mut stream, _) = vox_core::node::ipc::open_as(&held.at)
        .await
        .map_err(|e| crate::client::said(&held.at, e))?;
    // Both paths are used by the daemon, whose working directory is not this command's: a
    // relative one is made absolute here, where it was typed.
    let absolute = |p: std::path::PathBuf| {
        if p.is_absolute() {
            p
        } else {
            std::env::current_dir().map_or(p.clone(), |d| d.join(&p))
        }
    };
    let request = LanRequest {
        channel_id,
        helper: absolute(args.helper_socket.clone()),
        stats_file: args.stats_file.clone().map(absolute),
        allow: args.allow.iter().copied().collect(),
    };
    vox_core::node::ipc::write_frame(&mut stream, &request.to_bytes()).await?;
    let closed = crate::client::hold_until_closed(&mut held.client);
    tokio::pin!(closed);
    loop {
        tokio::select! {
            why = &mut closed => return Err(why),
            frame = vox_core::node::ipc::read_frame(&mut stream) => {
                let Ok(Some(body)) = frame else {
                    return Err((&mut closed).await);
                };
                match LanSaid::parse(&body) {
                    Some(LanSaid::Said(line)) => println!("{line}"),
                    Some(LanSaid::Failed(why)) => return Err(AppError::Usage(why)),
                    None => match vox_core::node::ipc::Frame::from_bytes(&body) {
                        Ok(vox_core::node::ipc::Frame::Error { reason }) => {
                            return Err(AppError::Usage(reason))
                        }
                        _ => {
                            return Err(AppError::Usage(
                                "the daemon answered `vox lan up` with something else".into(),
                            ))
                        }
                    },
                }
            }
        }
    }
}
