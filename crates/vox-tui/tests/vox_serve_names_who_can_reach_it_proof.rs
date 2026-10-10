//! ADR-017 4.2 — **`vox serve` names who can reach the service, and who in the room cannot**, by
//! name and not by count, and says it again when either changes. Driven through the shipped
//! binary.
//!
//! It printed the rule alone ("the identities you have trusted, once they join"), so a person
//! serving a port could not see who, of the people in the room, could reach it.
//!
//! Staging, nothing faked: a host `vox serve`s a port; a guest it trusts (as "the guest") joins
//! with the address and passphrase, and so does mallory, whom it does not trust. Then the host
//! trusts mallory with `vox trust add`.
//!
//! Asserted, from what `vox serve` printed (two lines each time: who can reach it, and who in
//! the room cannot):
//! - before anyone joins, nobody can reach it;
//! - with both in the room, "the guest" can reach it, and mallory, by her fingerprint (the thing
//!   a person needs to `vox trust add` her), is in the room and cannot;
//! - once mallory is trusted, both can, by their names, and nobody in the room cannot.
//!
//! Mutation: every member counted as able to reach it (the trust check in
//! `tunnel_cli::audience` taken as true) turns it red.
//!
//! ADR-028 S-2 (#489) — **a share records what the service is, detected, never guessed**. The
//! host shares three services from this machine: one that greets with an SSH banner, named
//! `login`, on a port the system picks (never 22); a plain echo **named `ssh`**; and, with
//! `vox service add`, an HTTP server listening on this machine's LAN address, not loopback.
//! Asserted from what `vox serve` printed and what `vox service list` lists, on the host and on
//! the guest (which knows the kinds only from the room's log): `login` is `ssh`, the one named
//! `ssh` is plain `tcp`, and the LAN one is `http`.
//!
//! Mutation: the kind taken from the port (`ssh` for 22, else `tcp`) turns it red on `login`;
//! taken from the name, red on the echo named `ssh`.
//!
//! ADR-028 S-4 (#491) — **sharing is one step**. With mallory and the guest trusted, the host
//! runs `vox serve` with no service named while this proof listens on every interface on a
//! database port. Asserted from what it printed: the listening services are listed with their
//! programs (this proof's own among them, by name, on its port, "every interface"); once the
//! person picks it by port and names it `db`, the address members will use and who can reach it
//! (the guest and mallory, by name) are shown, and **before** it is shared it warns that it
//! listens on every interface and is on a database's port; then it is shared. The list says,
//! before it asks, that another user's services may be missing from it.
//!
//! Mutation: the warnings skipped turns it red; so does the list's line about another user's
//! services left out.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::time::Duration;

use world::{args, echo_service, fingerprint, mkdir, vox_once, PathKind, Setup, VoxProc, World};

const WITHIN: Duration = Duration::from_secs(60);
const CAN: &str = "can reach it now:";
const CANNOT: &str = "in the room and cannot (not trusted):";

/// The first audience `vox serve` said that satisfies `pred`, as its two lines `(can, cannot)`,
/// waited for; `None` if it said none within [`WITHIN`].
fn audience(host: &mut VoxProc, pred: impl Fn(&str, &str) -> bool) -> Option<(String, String)> {
    let deadline = std::time::Instant::now() + WITHIN;
    loop {
        let said = host.transcript();
        let lines: Vec<&str> = said.lines().map(str::trim).collect();
        let found = lines.windows(2).find_map(|w| {
            let can = w[0].strip_prefix(CAN)?.trim();
            let cannot = w[1].strip_prefix(CANNOT)?.trim();
            pred(can, cannot).then(|| (can.to_owned(), cannot.to_owned()))
        });
        if found.is_some() || std::time::Instant::now() >= deadline {
            return found;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
#[ignore = "an anchor and three vox daemons with production Argon2id; CI runs it in release"]
fn vox_serve_names_who_can_reach_it_and_who_cannot() {
    watchdog::arm();
    let login = ssh_banner_service();
    let mut w = World::build(&Setup {
        specs: vec![format!("login={login}"), format!("ssh={}", echo_service())],
        trusted: true,
        path: PathKind::Direct,
        guest_leg: None,
    });
    let mallory = w.tmp.path().join("mallory");
    mkdir(&mallory.join("cfg"));
    let mallory_fp = fingerprint(&mallory, "mallory");
    let (ok, took, out, err) = w.join(&mallory);
    assert!(
        ok,
        "PRODUCT (staging): mallory's `vox connect` failed after {took:?}: {out}{err}"
    );
    // What `vox connect` says to do next is true of this release: the daemon's proxy carries the
    // name while a node is attached, so nothing has to be left running.
    assert!(
        out.lines().any(|l| l.trim_start().starts_with(
            "reach a service as <service>.<node>.<room>.vox through the daemon's proxy, running \
             while a node is attached"
        )) && !out.contains("with `vox up` running"),
        "PRODUCT: `vox connect` must say a service is reached through the daemon's proxy while a \
         node is attached, not that `vox up` must be running; it said:\n{out}"
    );

    let host = w.host.as_mut().expect("APPARATUS: the world's host runs");
    let alone = audience(host, |_, _| true);
    let both = audience(host, |_, cannot| cannot.contains(&mallory_fp));
    eprintln!("[proof] alone: {alone:?}\n[proof] with the guest and mallory: {both:?}");
    assert!(
        alone
            .as_ref()
            .is_some_and(|(can, cannot)| can == "nobody yet" && cannot == "nobody"),
        "PRODUCT: before anyone joins, `vox serve` must say nobody can reach it; it said \
         {alone:?}:\n{}",
        host.transcript()
    );
    assert!(
        both.as_ref()
            .is_some_and(|(can, cannot)| can == "the guest" && *cannot == mallory_fp),
        "PRODUCT: with the trusted guest and untrusted mallory in the room, `vox serve` must name \
         the guest, by name, as able to reach it, and mallory, by fingerprint ({mallory_fp}), as \
         in the room and unable; it said {both:?}:\n{}",
        host.transcript()
    );

    // mallory is trusted: the lists change, and are said again.
    let (ok, out, err) = vox_once(
        &w.host_dir,
        &args(&["trust", "add", &mallory_fp, "--name", "mallory"]),
    );
    assert!(
        ok,
        "PRODUCT (staging): the host's `vox trust add` of mallory: {out}{err}"
    );
    let host = w.host.as_mut().expect("APPARATUS: the world's host runs");
    let trusted = audience(host, |can, _| can.contains("mallory"));
    eprintln!("[proof] once mallory is trusted: {trusted:?}");
    assert!(
        trusted.as_ref().is_some_and(|(can, cannot)| {
            let mut names: Vec<&str> = can.split(", ").collect();
            names.sort_unstable();
            names == ["mallory", "the guest"] && cannot == "nobody"
        }),
        "PRODUCT: once mallory is trusted, `vox serve` must say both can reach it, by name, and \
         that nobody in the room cannot; it said {trusted:?}:\n{}",
        host.transcript()
    );

    // ADR-028 S-2: what each share is, as `vox serve` said it when it shared them.
    let host = w.host.as_mut().expect("APPARATUS: the world's host runs");
    let said = host.transcript();
    let sharing = |name: &str| {
        said.lines()
            .find(|l| l.starts_with("sharing ") && l.contains(&format!(" as {name} — ")))
            .map(str::to_owned)
    };
    let (login_said, ssh_said) = (sharing("login"), sharing("ssh"));
    eprintln!("[proof] vox serve said: {login_said:?} / {ssh_said:?}");
    assert!(
        login_said.as_deref().is_some_and(|l| l.ends_with(" (ssh)")),
        "PRODUCT: `login` greets with an SSH banner on port {login}, so `vox serve` must say it \
         shares it as ssh; it said {login_said:?}:\n{said}"
    );
    assert!(
        ssh_said.as_deref().is_some_and(|l| l.ends_with(" (tcp)")),
        "PRODUCT: the service named `ssh` is a plain echo, so `vox serve` must say it shares it \
         as tcp, not from its name; it said {ssh_said:?}:\n{said}"
    );

    // An HTTP server on this machine's LAN address, shared with `vox service add`.
    let web = http_service(lan_address());
    let (ok, out, err) = vox_once(
        &w.host_dir,
        &args(&["service", "add", &w.room, "pages", &web.to_string()]),
    );
    assert!(
        ok,
        "PRODUCT (staging): the host's `vox service add` of {web}: {out}{err}"
    );
    let (ok, out, err) = vox_once(&w.host_dir, &args(&["service", "list", &w.room]));
    eprintln!("[proof] the host's vox service list:\n{out}{err}");
    for (name, kind) in [("login", "ssh"), ("ssh", "tcp"), ("pages", "http")] {
        assert!(
            ok && listed_as(&out, name, kind),
            "PRODUCT: the host's `vox service list` must list `{name}` as {kind}; it said:\n\
             {out}{err}"
        );
    }

    // The guest knows them only from the room's log: its node runs, as a person's does, and
    // lists what has reached it.
    let pass_file = w.guest_dir.join("passphrases");
    std::fs::write(&pass_file, format!("{}\n", world::IDENTITY))
        .unwrap_or_else(|e| panic!("APPARATUS: the guest's passphrase file: {e}"));
    let mut guest = VoxProc::spawn(
        "guest daemon",
        &w.guest_dir,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            &w.guest_anchor,
            "--passphrase-file",
            &world::utf8(&pass_file),
        ]),
    );
    let want = [("login", "ssh"), ("ssh", "tcp"), ("pages", "http")];
    let deadline = std::time::Instant::now() + WITHIN;
    let (ok, said) = loop {
        let (ok, out, err) =
            world::vox_once_plain(&w.guest_dir, &args(&["service", "list", &w.room]));
        let all = ok && want.iter().all(|(name, kind)| listed_as(&out, name, kind));
        if all || std::time::Instant::now() >= deadline {
            break (all, format!("{out}{err}"));
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    eprintln!("[proof] the guest's vox service list:\n{said}");
    assert!(
        ok,
        "PRODUCT: within {WITHIN:?} the guest's `vox service list` must list `login` as ssh, \
         `ssh` as tcp and `pages` as http, as the host's shares said; it said:\n{said}\n\
         its daemon said:\n{}",
        guest.transcript()
    );
    drop(guest);

    // ADR-028 S-4: `vox serve` with nothing named, picking a database listening everywhere.
    let (db, db_port) = everywhere_on_a_database_port();
    let mut pick = VoxProc::spawn_fed(
        "vox serve (one step)",
        &w.host_dir,
        &args(&["serve", "--name", "db-room"]),
        &format!("{db_port}\ndb\ny\n"),
    );
    let shared = pick.line_within(WITHIN, |l| {
        l.starts_with("sharing ") && l.contains(" as db — ")
    });
    let said = pick.transcript();
    eprintln!("[proof] one-step vox serve said:\n{said}");
    let lines: Vec<&str> = said.lines().collect();
    let at = |pred: &dyn Fn(&str) -> bool| lines.iter().position(|l| pred(l));
    let listed = lines
        .iter()
        .find(|l| l.contains(&format!("0.0.0.0:{db_port}")) && l.contains("(every interface)"));
    assert!(
        listed.is_some_and(|l| l.contains("vox_serve")),
        "PRODUCT: `vox serve` with no service named must list what listens here, with its \
         program: this proof's ({db_port}, every interface) by name; it said:\n{said}"
    );
    // Unprivileged, the list cannot show every service: it says so, before the question.
    let unseen = at(&|l: &str| {
        l.contains("another user's services") && l.contains("`vox serve ssh=22` names port 22 ssh")
    });
    let asked = at(&|l: &str| l.starts_with("share which?"));
    assert!(
        unseen.zip(asked).is_some_and(|(u, a)| u < a),
        "PRODUCT: `vox serve`'s list must say that another user's services may be missing from \
         it, before it asks which to share; it said:\n{said}"
    );
    let me = &w.host_fp;
    let preview = at(&|l: &str| l.contains(&format!("members will reach it as db.{me}.")));
    let who = lines
        .iter()
        .find(|l| l.starts_with("who can reach it: each node you trust"));
    assert!(
        preview.is_some() && who.is_some_and(|l| l.contains("the guest") && l.contains("mallory")),
        "PRODUCT: before sharing, `vox serve` must show the address members will use and name \
         who can reach it (the guest and mallory); it said:\n{said}"
    );
    // Said as a sentence: the program and where it listens, without the list's column padding.
    // Every address it listens on is named, so 0.0.0.0 may come with others (a program bound to
    // 0.0.0.0 and 127.0.0.1 too reads "on 0.0.0.0:5432, 127.0.0.1:5432, tcp").
    let everywhere = at(&|l: &str| {
        l.starts_with("warning: `db` (")
            && l.contains(&format!(" on 0.0.0.0:{db_port}"))
            && l.contains(", tcp) listens on every interface")
            && !l.contains("  ")
    });
    let database =
        at(&|l: &str| l.starts_with("warning: `db`") && l.contains(&format!("port {db_port}")));
    let sharing = at(&|l: &str| l.starts_with("sharing ") && l.contains(" as db — "));
    assert!(
        shared.is_some()
            && everywhere.zip(sharing).is_some_and(|(w, s)| w < s)
            && database.zip(sharing).is_some_and(|(d, s)| d < s),
        "PRODUCT: `vox serve` must warn, in a sentence (\"`db` (<program> on 0.0.0.0:{db_port}, \
         tcp) listens on every interface\"), that `db` listens on every interface and is on a \
         database's port ({db_port}) before it shares it, then share it; it said:\n{said}"
    );
    drop(db);
}

/// A listener on every interface on a well-known database port this machine has free: this
/// proof's own, held for as long as the returned listener is.
fn everywhere_on_a_database_port() -> (TcpListener, u16) {
    for port in [5432, 3306, 6379, 27017, 9200, 11211, 5984, 1433] {
        let Ok(l) = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)) else {
            continue;
        };
        let held = l
            .try_clone()
            .unwrap_or_else(|e| panic!("APPARATUS: the database stand-in's listener: {e}"));
        std::thread::spawn(move || {
            // Accepted and held, so a probe of it finds a silent service.
            let mut open = Vec::new();
            for s in held.incoming().map_while(Result::ok) {
                open.push(s);
            }
        });
        return (l, port);
    }
    panic!("APPARATUS: every database port this proof can stand in on is taken on this machine")
}

/// Whether `vox service list`'s output lists the service `name` as `kind`:
/// `  <name>.<node>.<room>.vox  by <who>  <kind>`.
fn listed_as(out: &str, name: &str, kind: &str) -> bool {
    out.lines().any(|l| {
        let l = l.trim();
        l.starts_with(&format!("{name}."))
            && l.contains("  by ")
            && l.ends_with(&format!("  {kind}"))
    })
}

/// A service that greets every connection with an SSH banner, as `sshd` does, on a port the
/// system picks. Returns its port.
fn ssh_banner_service() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("APPARATUS: could not bind the SSH-banner service: {e}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("APPARATUS: the SSH-banner service has no address: {e}"))
        .port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let _ = s.write_all(b"SSH-2.0-OpenSSH_9.8\r\n");
                let mut buf = [0u8; 4096];
                while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
            });
        }
    });
    port
}

/// A minimal HTTP server listening on `ip`: every request is answered `200 OK`. Returns where
/// it listens.
fn http_service(ip: IpAddr) -> SocketAddr {
    let listener = TcpListener::bind((ip, 0))
        .unwrap_or_else(|e| panic!("APPARATUS: could not bind the HTTP service on {ip}: {e}"));
    let at = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("APPARATUS: the HTTP service has no address: {e}"));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                if matches!(s.read(&mut buf), Ok(n) if n > 0) {
                    let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
                }
            });
        }
    });
    at
}

/// This machine's own LAN address: the source address of a route out (a UDP socket connected
/// to a documentation address sends nothing).
fn lan_address() -> IpAddr {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .unwrap_or_else(|e| panic!("APPARATUS: could not bind a UDP socket: {e}"));
    sock.connect("192.0.2.1:9").unwrap_or_else(|e| {
        panic!("APPARATUS: this machine has no route out for a LAN address: {e}")
    });
    let ip = sock
        .local_addr()
        .unwrap_or_else(|e| panic!("APPARATUS: no local address: {e}"))
        .ip();
    assert!(
        !ip.is_loopback() && !ip.is_unspecified(),
        "APPARATUS: this machine has no LAN address ({ip})"
    );
    ip
}
