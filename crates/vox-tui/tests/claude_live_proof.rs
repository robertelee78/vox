//! ADR-020 / D10 (#408) — **a live Claude Code turn reads the room through its node's hook, and
//! only what its node trusts.**
//!
//! `agent_hook_proof` and the other hook proofs drive `vox agent hook` with a stand-in for the
//! harness. This one runs Claude Code itself, `claude -p`, on the decider's request (2026-10-04):
//!
//! 1. one data root and its daemon, holding three nodes made as the skill makes them (`vox node
//!    create`, ADR-026 N-6): `person`, whose room it is, and two agent nodes, `claude-t` and
//!    `claude-u`, which both join it. `person` trusts both agents, so it offers both its key.
//!    `claude-t` trusts `person`; `claude-u` does not, so it takes no key from `person` and reads
//!    nothing of theirs (V210-118). `person` posts a codeword with `vox room post` — a token that
//!    appears nowhere in the prompt, the settings or Claude Code;
//! 2. two isolated `CLAUDE_CONFIG_DIR`s, each holding exactly the `settings.json` that `vox agent
//!    plugin claude --node <its node>` prints, and nothing of the operator's Claude configuration;
//! 3. one `claude -p` turn for each, the same prompt, which asks for a codeword if the context
//!    holds one. **Trusted** (`claude-t`): the codeword is in what Claude Code recorded the turn
//!    was given (its session transcript, where the hook's context lands) and in the answer.
//!    **Untrusted** (`claude-u`): in neither.
//!
//! The untrusted turn is the control: the same binary, prompt, wiring and room, with the one
//! thing under test (the node's trust of the poster) removed.
//!
//! ## Every Claude Code here is sandboxed, and holds one credential
//!
//! A model's turn may run a shell. Every `claude -p` runs under macOS `sandbox-exec` whose
//! profile ([`oc_sandbox::sandbox_profile`]) reads only the system, Claude Code's own install
//! directory, the `vox` binary and this run's root, and writes only the root. Before any turn a
//! shell under that profile must fail to read, find or list a canary planted in the operator's
//! real HOME, and must fail to read Claude Code's sign-in from the operator's keychain; no turn's
//! output, nor its transcript, may hold the canary's text. Claude Code runs in a cleared
//! environment: `PATH` (this run's `bin` with a copy of `vox`, then the system's), a `HOME`,
//! `TMPDIR` and `CLAUDE_CONFIG_DIR` inside the root, and the run's `VOX_DATA_DIR` /
//! `VOX_CONFIG_DIR` for the hook.
//!
//! **The sign-in.** Claude Code keeps the operator's OAuth sign-in in the login keychain (item
//! `Claude Code-credentials`), not in a file. This proof — outside the sandbox, as the operator —
//! reads that item once with `security find-generic-password` and hands the sandboxed `claude`
//! its **access token alone**, as `CLAUDE_CODE_OAUTH_TOKEN`. The refresh token never enters the
//! sandbox, so no turn can rotate the operator's sign-in, and nothing of `~/.claude` is copied.
//! A token with less than [`TOKEN_MARGIN`] left is `CANNOT MEASURE`: the operator runs `claude`
//! once, which refreshes it. Nothing here ever prints the token, runs a login, or answers a
//! setup screen; `claude -p` shows none.
//!
//! **No setting or hook of the operator's runs.** `CLAUDE_CONFIG_DIR` and `HOME` are inside the
//! root, and the sandbox cannot read the real HOME; every turn's output is checked not to name
//! the operator's `~/.claude`.
//!
//! **A dry run stops before Claude Code.** With `VOX_PROOF_STOP_BEFORE_CLAUDE=1` the proof does
//! its setup — the nodes, daemon, room, trust and codeword, both config dirs, the sandbox probe —
//! and runs each node's printed hook under the sandbox as Claude Code would run it, then stops
//! before reading the sign-in or starting Claude Code. It says `STOPPED BEFORE CLAUDE` and passes.
//!
//! **Which side a red is on.** What `vox` did — the room absent from the trusted turn's context,
//! or present in the untrusted one's — is `PRODUCT:`. The model provider refusing, Claude Code
//! not starting, a sign-in too old, or a fault of this proof's own is `APPARATUS:` / `CANNOT
//! MEASURE`. A trusted turn whose transcript holds the codeword but whose answer does not is
//! `CANNOT MEASURE` for the answer (the model's choice), and green for the injection, which is
//! the claim.
//!
//! **Mutation that must turn it red:** the trusted config dir's settings printed for another
//! node (`--node claude-u`) → the trusted turn's context has no codeword.

// Optional (decider, 2026-10-01): it blocks nothing, and only a build with `live-model-sandbox`
// starts a model (2026-10-02). docs/release/optional-proofs.md says how to run it.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(
    a_live_claude_turn_reads_the_room_only_through_what_its_node_trusts,
    a_live_claude_session_is_followed_answered_and_interrupted_from_vox
);

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/oc_sandbox.rs"]
mod oc_sandbox;

#[path = "support/typed.rs"]
mod typed;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// The person whose room it is.
const PERSON: &str = "person";
/// The agent node that trusts the person.
const TRUSTED: &str = "claude-t";
/// The agent node that does not.
const UNTRUSTED: &str = "claude-u";
/// The keychain item where Claude Code keeps the operator's sign-in.
const KEYCHAIN_ITEM: &str = "Claude Code-credentials";
/// The least life a sign-in must have left for this run to use it: two turns and some slack.
const TOKEN_MARGIN: Duration = Duration::from_secs(15 * 60);

/// What the model is asked: tiny, and naming no codeword.
const PROMPT: &str = "If your context contains a Vox room message with a codeword, reply with \
                      only that codeword. Otherwise reply with only the word none. Do not run \
                      any command.";

/// The daemon `vox node attach` started for the run's data root, stopped by its own PID (the
/// one in `.daemon/lock`) when dropped.
struct Daemon(PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        let pid = std::fs::read_to_string(self.0.join(".daemon/lock"))
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok());
        if let Some(pid) = pid {
            let _ = Command::new("/bin/kill")
                .args(["-TERM", &pid.to_string()])
                .status();
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(15)
                && Command::new("/bin/kill")
                    .args(["-0", &pid.to_string()])
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success())
            {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// A dry run (`VOX_PROOF_STOP_BEFORE_CLAUDE=1`): everything up to reading the sign-in.
fn dry_run() -> bool {
    std::env::var("VOX_PROOF_STOP_BEFORE_CLAUDE").is_ok_and(|v| v == "1")
}

/// `vox args` as `node`, against the run's data root.
fn vox(
    data: &Path,
    cfg: &Path,
    node: &str,
    args: &[&str],
    input: Option<&str>,
) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        // Every node has a passphrase (ADR-028 K-11); each is attached before Claude Code starts,
        // and an agent's hook finds its node attached.
        .env("VOX_IDENTITY_PASSPHRASE", "an identity passphrase")
        .env("VOX_NODE", node)
        .env("VOX_LISTEN", "127.0.0.1:0")
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ROOM_PASSPHRASE");
    // Nothing of a terminal or a harness session this proof did not make: a `vox` run from inside
    // the operator's own Claude Code session would otherwise inherit its tmux pane and sockets.
    for (k, _) in std::env::vars_os() {
        let name = k.to_string_lossy();
        if ["TMUX", "CLAUDE", "CODEX", "OPENCODE", "VOX_SESSION"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            cmd.env_remove(&k);
        }
    }
    // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
    if typed::is_keyring_change(args) {
        let (ok, shown) = typed::keyring(&cmd);
        return (ok, shown.clone(), shown);
    }
    let mut child = cmd
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start `vox {}`: {e}", args.join(" ")));
    if let Some(text) = input {
        let mut pipe = child
            .stdin
            .take()
            .unwrap_or_else(|| panic!("APPARATUS: `vox {}` has no stdin pipe", args.join(" ")));
        let _ = pipe.write_all(text.as_bytes());
        drop(pipe);
    }
    let out = child.wait_with_output().unwrap_or_else(|e| {
        panic!(
            "APPARATUS: cannot collect `vox {}`'s output: {e}",
            args.join(" ")
        )
    });
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `vox args` as `node`, which must succeed: `PRODUCT (staging)` if it does not.
fn staged(data: &Path, cfg: &Path, node: &str, args: &[&str], input: Option<&str>) -> String {
    let (ok, out, err) = vox(data, cfg, node, args, input);
    assert!(
        ok,
        "PRODUCT (staging): `vox {}` as {node} failed: {out}{err}",
        args.join(" ")
    );
    out
}

/// The installed Claude Code, every symlink resolved, and the directory holding it: all of the
/// operator's install the sandbox may read.
fn claude_install() -> (PathBuf, PathBuf) {
    let found = std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("claude"))
                .find(|p| p.is_file())
        })
        .unwrap_or_else(|| panic!("APPARATUS, CANNOT MEASURE: claude is not on PATH"));
    let bin = oc_sandbox::real(&found);
    let dir = bin
        .parent()
        .unwrap_or_else(|| panic!("APPARATUS: claude's binary has no directory"))
        .to_path_buf();
    (bin, dir)
}

/// The operator's Claude Code access token, read from the keychain by this process (never by
/// the sandbox), and checked to have [`TOKEN_MARGIN`] left. Never printed.
fn access_token(real_home: &Path) -> String {
    // The operator's login keychain by its path: this test's children run with a temporary HOME
    // (`watchdog::temp_home`), whose keychain search list is empty.
    let login = real_home.join("Library/Keychains/login.keychain-db");
    let out = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", KEYCHAIN_ITEM, "-w"])
        .arg(&login)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run security: {e}"));
    assert!(
        out.status.success(),
        "CANNOT MEASURE: no `{KEYCHAIN_ITEM}` item in the login keychain, so no Claude Code turn \
         can run; sign in to Claude Code (this proof never does)"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
        panic!("APPARATUS: the `{KEYCHAIN_ITEM}` item is not the JSON Claude Code writes")
    });
    // Only the access token and its expiry are kept; the item, refresh token included, is dropped
    // here, and its bytes with it.
    let oauth = &v["claudeAiOauth"];
    let token = oauth["accessToken"]
        .as_str()
        .filter(|t| !t.is_empty())
        .map(str::to_owned);
    let expires = oauth["expiresAt"].as_u64().unwrap_or(0) / 1000;
    drop(v);
    drop(out);
    let token = token.unwrap_or_else(|| {
        panic!("CANNOT MEASURE: the `{KEYCHAIN_ITEM}` item holds no access token")
    });
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|e| panic!("APPARATUS: the clock is before 1970: {e}"))
        .as_secs();
    let left = expires.saturating_sub(now);
    assert!(
        left >= TOKEN_MARGIN.as_secs(),
        "CANNOT MEASURE: the operator's Claude Code sign-in has {left} s left, under {TOKEN_MARGIN:?}; \
         run `claude` once (it refreshes its own sign-in), then run this again"
    );
    println!(
        "[proof] the operator's Claude Code access token, read from the keychain by the proof: \
         {} min left; the refresh token stays in the keychain",
        left / 60
    );
    token
}

/// One isolated Claude Code: its `CLAUDE_CONFIG_DIR`, `HOME` and `TMPDIR`, all under the root.
struct ClaudeHome {
    config: PathBuf,
    home: PathBuf,
    tmp: PathBuf,
}

impl ClaudeHome {
    fn new(root: &Path, name: &str) -> Self {
        let base = root.join(name);
        let me = Self {
            config: base.join("claude"),
            home: base.join("home"),
            tmp: base.join("tmp"),
        };
        for d in [&me.config, &me.home, &me.tmp] {
            std::fs::create_dir_all(d)
                .unwrap_or_else(|e| panic!("APPARATUS: cannot make {d:?}: {e}"));
        }
        me
    }

    /// `program` in a cleared environment: only what Claude Code and the hook need, every path in
    /// the run's root.
    fn command(&self, program: &Path, path: &str, data: &Path, cfg: &Path) -> Command {
        let mut c = Command::new(program);
        c.env_clear()
            // A proof's daemon never takes port 1080 (.cargo/config.toml).
            .env("VOX_PROXY", "127.0.0.1:0")
            .env("PATH", path)
            .env("HOME", &self.home)
            .env("TMPDIR", &self.tmp)
            // Claude Code's own scratch directory, `/tmp/claude-<uid>` unless told otherwise: the
            // operator's other Claude Code sessions use that one.
            .env("CLAUDE_CODE_TMPDIR", &self.tmp)
            .env("CLAUDE_CONFIG_DIR", &self.config)
            .env("VOX_DATA_DIR", data)
            .env("VOX_CONFIG_DIR", cfg)
            .env("LANG", "en_US.UTF-8");
        c
    }
}

/// Every `.jsonl` file under `dir`, recursively, read as text and joined: Claude Code's
/// transcripts.
fn transcripts(dir: &Path) -> String {
    let mut out = String::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "jsonl") {
                out += &std::fs::read_to_string(&p).unwrap_or_default();
                out.push('\n');
            }
        }
    }
    out
}

/// The line of `text` holding `needle`, cut to a readable length around it.
fn evidence(text: &str, needle: &str) -> Option<String> {
    let line = text.lines().find(|l| l.contains(needle))?;
    let at = line.find(needle)?;
    let mut from = at.saturating_sub(240);
    while !line.is_char_boundary(from) {
        from -= 1;
    }
    let mut to = (at + needle.len() + 120).min(line.len());
    while !line.is_char_boundary(to) {
        to += 1;
    }
    Some(line[from..to].to_owned())
}

/// How many files are under `dir`, and those (by path relative to `dir`) whose bytes hold any of
/// `needles`. The `vox` copy in `bin/` is skipped: it is this build's binary, not a turn's output.
fn files_holding(dir: &Path, needles: &[&str]) -> (usize, Vec<String>) {
    let (mut count, mut hits) = (0, Vec::new());
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            let Ok(kind) = e.file_type() else { continue };
            if kind.is_dir() {
                if p != dir.join("bin") {
                    stack.push(p);
                }
            } else if kind.is_file() {
                count += 1;
                let bytes = std::fs::read(&p).unwrap_or_default();
                if needles
                    .iter()
                    .any(|n| bytes.windows(n.len()).any(|w| w == n.as_bytes()))
                {
                    hits.push(p.strip_prefix(dir).unwrap_or(&p).display().to_string());
                }
            }
        }
    }
    (count, hits)
}

/// What a turn left: everything it printed, its answer, and its transcripts.
struct Turn {
    said: String,
    answer: String,
    logs: String,
}

/// The rooms `node` holds, by `vox status --json`: (id, received key generations).
fn received(data: &Path, cfg: &Path, node: &str) -> Vec<(String, u64)> {
    let out = staged(data, cfg, node, &["status", "--json"], None);
    let v: serde_json::Value = serde_json::from_str(out.trim())
        .unwrap_or_else(|e| panic!("PRODUCT: {node}'s `vox status --json` is not JSON ({e})"));
    v["rooms"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            (
                r["id"].as_str().unwrap_or_default().to_owned(),
                r["received_key_generations"].as_u64().unwrap_or(0),
            )
        })
        .collect()
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "drives a real Claude Code model turn; optional, on the decider's request, in release"]
fn a_live_claude_turn_reads_the_room_only_through_what_its_node_trusts() {
    watchdog::arm_for(Duration::from_secs(900));
    if !oc_sandbox::live_model_allowed(
        "claude_live_proof::a_live_claude_turn_reads_the_room_only_through_what_its_node_trusts",
    ) {
        return;
    }
    let (claude, claude_dir) = claude_install();
    let real_home = watchdog::temp_home::real_home()
        .unwrap_or_else(|| panic!("APPARATUS: HOME is unset, so the operator's files are unknown"));

    // ---- the run's root: short, so the daemon's socket path fits ----
    std::fs::create_dir_all("/private/tmp/vc")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make /private/tmp/vc: {e}"));
    let tmp = tempfile::Builder::new()
        .prefix("cll-")
        .tempdir_in("/private/tmp/vc")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make a temp directory: {e}"));
    let root = oc_sandbox::real(tmp.path());
    let data = root.join("vd");
    let cfg = root.join("vc");
    let bin = root.join("bin");
    let work = root.join("work");
    for d in [&bin, &work] {
        std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("APPARATUS: cannot make {d:?}: {e}"));
    }
    // A copy of this `vox` (not a link) where the hook's bare `vox` finds it.
    std::fs::copy(VOX, bin.join("vox"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot copy vox into the run: {e}"));
    let path = format!("{}:{}", bin.display(), oc_sandbox::SANDBOX_PATH);

    // ---- three nodes in one daemon: the person, and two agents ----
    for node in [PERSON, TRUSTED, UNTRUSTED] {
        staged(&data, &cfg, node, &["node", "create", node], None);
    }
    let (ok, out, err) = vox(&data, &cfg, PERSON, &["node", "attach", PERSON], None);
    let _daemon = Daemon(data.clone());
    assert!(
        ok,
        "PRODUCT (staging): `vox node attach {PERSON}` (which starts the daemon) failed: {out}{err}"
    );
    for node in [TRUSTED, UNTRUSTED] {
        staged(&data, &cfg, node, &["node", "attach", node], None);
    }
    let fp = |node: &str| staged(&data, &cfg, node, &["id"], None).trim().to_owned();
    let (person_fp, t_fp, u_fp) = (fp(PERSON), fp(TRUSTED), fp(UNTRUSTED));

    // ---- the person's room, both agents in it; trust as the claim needs it ----
    staged(
        &data,
        &cfg,
        PERSON,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "agents",
        ],
        Some("channel passphrase\n"),
    );
    let list = staged(&data, &cfg, PERSON, &["room", "list"], None);
    let room = list
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("PRODUCT (staging): `vox room list` shows no room: {list:?}"))
        .to_owned();
    let link = staged(&data, &cfg, PERSON, &["room", "link", &room], None)
        .trim()
        .to_owned();
    for (agent, agent_fp) in [(TRUSTED, &t_fp), (UNTRUSTED, &u_fp)] {
        staged(
            &data,
            &cfg,
            PERSON,
            &["trust", "add", agent_fp, "--name", agent],
            None,
        );
        staged(
            &data,
            &cfg,
            agent,
            &["room", "join", "--passphrase-file", "-", &link],
            Some("channel passphrase\n"),
        );
    }
    // The trusted agent's owner trusts the person; the untrusted agent's does not.
    staged(
        &data,
        &cfg,
        TRUSTED,
        &["trust", "add", &person_fp, "--name", PERSON],
        None,
    );
    let codeword = format!(
        "ZORVEL-{:06}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|e| panic!("APPARATUS: the clock is before 1970: {e}"))
            .subsec_micros()
    );
    staged(
        &data,
        &cfg,
        PERSON,
        &[
            "room",
            "post",
            &room,
            &format!("The codeword for this mission is {codeword}."),
        ],
        None,
    );
    println!(
        "[proof] room {room} holds codeword {codeword}, posted by {PERSON} through `vox room post`"
    );

    // The premise, as each agent's own report says it: the trusted one holds the person's key and
    // reads the codeword; the untrusted one holds no key and reads nothing of it.
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let reads = staged(&data, &cfg, TRUSTED, &["room", "read", &room], None);
        if reads.contains(&codeword) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): {TRUSTED}, which trusts {PERSON}, never read the codeword within \
             120 s: {:?}; `vox room read`: {reads}",
            received(&data, &cfg, TRUSTED)
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    let u_reads = staged(&data, &cfg, UNTRUSTED, &["room", "read", &room], None);
    let u_keys = received(&data, &cfg, UNTRUSTED);
    println!(
        "[proof] premise: {TRUSTED} reads the codeword; {UNTRUSTED} holds {u_keys:?} received key \
         generations and its `vox room read` holds the codeword: {}",
        u_reads.contains(&codeword)
    );
    assert!(
        !u_reads.contains(&codeword),
        "PRODUCT: {UNTRUSTED}, which does not trust {PERSON}, reads the person's codeword: {u_reads}"
    );

    // ---- two isolated Claude Code config dirs, each with exactly what `vox agent plugin claude`
    // prints for its node ----
    let homes: Vec<(&str, ClaudeHome)> = [TRUSTED, UNTRUSTED]
        .into_iter()
        .map(|node| {
            let plugin = Command::new(VOX)
                .args(["agent", "plugin", "claude", "--node", node])
                .output()
                .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox agent plugin claude: {e}"));
            assert!(
                plugin.status.success(),
                "PRODUCT: `vox agent plugin claude --node {node}` failed"
            );
            let h = ClaudeHome::new(&root, node);
            std::fs::write(h.config.join("settings.json"), &plugin.stdout)
                .unwrap_or_else(|e| panic!("APPARATUS: cannot write settings.json: {e}"));
            (node, h)
        })
        .collect();

    // ---- the sandbox, probed against the canary and the keychain before any turn ----
    let canary = oc_sandbox::Canary::plant();
    let profile = root.join("claude.sb");
    std::fs::write(
        &profile,
        oc_sandbox::sandbox_profile(&[&root], &[&claude_dir]),
    )
    .unwrap_or_else(|e| panic!("APPARATUS: cannot write the sandbox profile: {e}"));
    oc_sandbox::probe_profile(&profile, &canary, "claude");
    let keychain = Command::new("/usr/bin/sandbox-exec")
        .arg("-f")
        .arg(&profile)
        .args([
            "/usr/bin/security",
            "find-generic-password",
            "-s",
            KEYCHAIN_ITEM,
            "-w",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run the keychain probe: {e}"));
    let leaked = keychain.status.success() && !keychain.stdout.is_empty();
    println!(
        "[proof] sandbox probe (claude): reading `{KEYCHAIN_ITEM}` from the keychain inside the \
         sandbox: {} (exit {:?})",
        if leaked { "SUCCEEDED" } else { "refused" },
        keychain.status.code()
    );
    assert!(
        !leaked,
        "APPARATUS: the sandbox leaked: a sandboxed shell read the operator's Claude Code sign-in \
         from the keychain. Stop every live-model run until it is fixed."
    );

    // ---- each node's printed hook, run in the sandbox as Claude Code runs it ----
    for (node, h) in &homes {
        let command = format!("vox agent hook --node {node}");
        let mut hook = h.command(Path::new("/usr/bin/sandbox-exec"), &path, &data, &cfg);
        hook.arg("-f")
            .arg(&profile)
            .args(["/bin/sh", "-c", &command])
            .current_dir(&work)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = hook
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot run the hook in the sandbox: {e}"));
        let _ = child.stdin.take().map(|mut i| {
            i.write_all(
                br#"{"hook_event_name":"UserPromptSubmit","session_id":"probe","prompt":"hi"}"#,
            )
        });
        let out = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot collect the hook's output: {e}"));
        let drained = String::from_utf8_lossy(&out.stdout).into_owned();
        canary.check(&drained, "the sandboxed hook's output");
        let holds = drained.contains(&codeword);
        println!(
            "[proof] {node}'s printed hook, run in the sandbox as Claude Code runs it: exit {:?}, \
             drain holds the codeword: {holds}",
            out.status.code()
        );
        assert!(
            out.status.success() && holds == (*node == TRUSTED),
            "PRODUCT: `{command}`, run as Claude Code would run it in the sandbox, {} the codeword: \
             {drained}\nstderr: {}",
            if holds { "drained" } else { "did not drain" },
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // ---- a dry run stops here: no sign-in read, no Claude Code started ----
    if dry_run() {
        println!(
            "[proof] STOPPED BEFORE CLAUDE: nodes, daemon, room {room}, trust, codeword, both config \
             dirs, the sandbox probes and both hooks are ready; no sign-in was read and no Claude \
             Code was started"
        );
        return;
    }

    let token = access_token(real_home);

    // ---- one turn for each node ----
    let turn = |node: &str, h: &ClaudeHome| -> Turn {
        let mut cmd = h.command(Path::new("/usr/bin/sandbox-exec"), &path, &data, &cfg);
        cmd.env("CLAUDE_CODE_OAUTH_TOKEN", &token)
            .arg("-f")
            .arg(&profile)
            .arg(&claude)
            .args(["-p", "--output-format", "json", PROMPT])
            .current_dir(&work)
            .stdin(Stdio::null());
        let started = Instant::now();
        let out = cmd
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot run claude -p: {e}"));
        let said = format!(
            "{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let answer = serde_json::from_slice::<serde_json::Value>(&out.stdout)
            .ok()
            .and_then(|v| v["result"].as_str().map(str::to_owned))
            .unwrap_or_default();
        let logs = transcripts(&h.config);
        for (what, text) in [
            ("output", &said),
            ("answer", &answer),
            ("transcript", &logs),
        ] {
            canary.check(text, &format!("the {node} Claude Code turn's {what}"));
            assert!(
                !text.contains(&token),
                "APPARATUS: the {node} turn's {what} holds the sign-in token"
            );
        }
        std::fs::write(root.join(format!("{node}.out")), &said)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot keep the turn's output: {e}"));
        println!(
            "[proof] {node} turn: exit {:?} after {:.1}s; answer {:?}",
            out.status.code(),
            started.elapsed().as_secs_f64(),
            answer.trim()
        );
        // **No setting or hook of the operator's ran** (module doc): nothing the turn said names
        // their `~/.claude`.
        let theirs = real_home.join(".claude").display().to_string();
        let named = said.contains(&theirs) || logs.contains(&theirs);
        println!("[proof] {node} turn: the operator's ~/.claude named in its output or transcript: {named}");
        assert!(
            !named,
            "APPARATUS: the {node} turn read the operator's ~/.claude: {}",
            evidence(&said, &theirs)
                .or_else(|| evidence(&logs, &theirs))
                .unwrap_or_default()
        );
        let low = said.to_ascii_lowercase();
        if !out.status.success()
            && [
                "401",
                "unauthorized",
                "invalid api key",
                "oauth",
                "login",
                "log in",
            ]
            .iter()
            .any(|s| low.contains(s))
        {
            panic!(
                "CANNOT MEASURE: the {node} Claude Code turn was refused for its sign-in; not \
                 retrying, and never driving a login. It said: {}",
                said.chars().take(3000).collect::<String>()
            );
        }
        assert!(
            out.status.success(),
            "APPARATUS, CANNOT MEASURE: the {node} Claude Code turn failed (exit {:?}): {}",
            out.status.code(),
            said.chars()
                .rev()
                .take(3000)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>()
        );
        Turn { said, answer, logs }
    };
    let u = turn(UNTRUSTED, &homes[1].1);
    let t = turn(TRUSTED, &homes[0].1);
    // **Nothing of the sign-in, nor the canary, was written anywhere in the run**: every file the
    // turns, their hooks and Claude Code left under the root, read and searched — config,
    // transcripts, session state, caches, logs.
    let (files, holding) = files_holding(&root, &[&token, &canary.text]);
    drop(token);
    println!(
        "[proof] every file the run left under its root ({files} files) searched for the token and the canary: {} hold either",
        holding.len()
    );
    assert!(
        holding.is_empty(),
        "APPARATUS: the sign-in token or the canary was written to {holding:?} under the run's root"
    );

    // ---- the verdicts ----
    let injected = evidence(&t.logs, &codeword);
    println!(
        "[proof] trusted turn, the transcript line that carries the room: {}",
        injected.as_deref().unwrap_or("(none)")
    );
    assert!(
        injected.is_some(),
        "PRODUCT: {TRUSTED}'s hook never fed the room to its turn: codeword {codeword} is not in \
         what Claude Code recorded it was given; its output: {}",
        t.said
    );
    assert!(
        !u.logs.contains(&codeword) && !u.said.contains(&codeword) && !u.answer.contains(&codeword),
        "PRODUCT: {UNTRUSTED}'s turn was given the person's codeword {codeword}, though its node \
         does not trust {PERSON}: {}",
        evidence(&u.logs, &codeword)
            .or_else(|| evidence(&u.said, &codeword))
            .unwrap_or_else(|| u.answer.clone())
    );
    println!("[proof] untrusted turn: codeword absent from its output, answer and transcript");
    assert!(
        t.answer.contains(&codeword),
        "CANNOT MEASURE (the answer only): the room reached the trusted turn's context, but the \
         model answered {:?}",
        t.answer.trim()
    );
    println!("[proof] trusted turn: the model answered with the codeword {codeword}");
}

/// ADR-029 SC-1, DR-1, DR-3, DR-4 (#540, #545, #544) — **a live, interactive Claude Code session
/// is followed, answered and interrupted from Vox**, as the person with drive does it, on the
/// decider's request (2026-10-06: strong live signal from every harness).
///
/// One data root and its daemon hold `person` and the agent node `claude-a` in one room; `claude-a`
/// trusts `person` with drive (typed at a terminal, ADR-028 K-13). The room map maps the run's work
/// directory to the room (ADR-029 RB-1), so a session started there works in it. Claude Code runs
/// **interactively** in a pane of a scratch tmux server (its socket under the run's root, never the
/// operator's), the server and the pane both confined by the live-proof sandbox (`oc_sandbox`, with
/// tmux's own install read-only), with `vox agent plugin claude --node claude-a`'s settings and the
/// operator's access token alone (the route `a_live_claude_turn_reads_…` documents).
///
/// 1. **Followed**: the person's `vox room session` shows the prompt typed at the terminal and the
///    call it makes;
/// 2. **Answered from the Session**: the call asks permission; the person approves it with
///    `vox room session … --approve <ref>`; Claude Code runs it (the file exists) and the Session
///    reads "approved here";
/// 3. **Interrupted from the Session**: during a long reply, `vox room session … --interrupt`
///    stops it, as Esc at the terminal does: the pane shows Claude Code's interruption.
///
/// **Never a sign-in or trust screen**: one appears, and the run stops there as `APPARATUS`,
/// typing nothing. **Which side a red is on**: what `vox` printed or did is `PRODUCT:`; the
/// sandbox, tmux, the pane, or the model's own choices are `APPARATUS:` / `CANNOT MEASURE`.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "drives a real interactive Claude Code session; optional, on the decider's request, in release"]
fn a_live_claude_session_is_followed_answered_and_interrupted_from_vox() {
    const AGENT: &str = "claude-a";
    const ROOM_PASS: &str = "channel passphrase";
    const MODEL: &str = "claude-haiku-4-5-20251001";
    watchdog::arm_for(Duration::from_secs(1200));
    if !oc_sandbox::live_model_allowed(
        "claude_live_proof::a_live_claude_session_is_followed_answered_and_interrupted_from_vox",
    ) {
        return;
    }
    let (claude, claude_dir) = claude_install();
    let real_home = watchdog::temp_home::real_home()
        .unwrap_or_else(|| panic!("APPARATUS: HOME is unset, so the operator's files are unknown"));
    let tmux = ["/opt/homebrew/bin/tmux", "/usr/local/bin/tmux"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("APPARATUS, CANNOT MEASURE: no tmux on this machine"));
    // tmux's own install, read-only inside the sandbox, so the server itself runs confined.
    let tmux_real = oc_sandbox::real(&tmux);
    let mut tmux_dirs: Vec<PathBuf> = vec![tmux_real
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| panic!("APPARATUS: tmux's install has no directory"))];
    for lib in ["utf8proc", "ncurses", "libevent"] {
        let p = PathBuf::from(format!("/opt/homebrew/opt/{lib}"));
        if p.exists() {
            tmux_dirs.push(oc_sandbox::real(&p));
        }
    }

    // ---- the run's root: short, so every socket path fits ----
    std::fs::create_dir_all("/private/tmp/vc")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make /private/tmp/vc: {e}"));
    let tmp = tempfile::Builder::new()
        .prefix("cls-")
        .tempdir_in("/private/tmp/vc")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make a temp directory: {e}"));
    let root = oc_sandbox::real(tmp.path());
    let data = root.join("vd");
    let cfg = root.join("vc");
    let bin = root.join("bin");
    let work = root.join("work");
    for d in [&bin, &work] {
        std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("APPARATUS: cannot make {d:?}: {e}"));
    }
    std::fs::copy(VOX, bin.join("vox"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot copy vox into the run: {e}"));
    let tmux_bin_dir = tmux
        .parent()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    // The hook finds `vox` and `tmux` (its pane claim names the tmux it runs under) on its PATH.
    let path = format!(
        "{}:{tmux_bin_dir}:{}",
        bin.display(),
        oc_sandbox::SANDBOX_PATH
    );

    // ---- two nodes, one room, drive ----
    for node in [PERSON, AGENT] {
        staged(&data, &cfg, node, &["node", "create", node], None);
    }
    let (ok, out, err) = vox(&data, &cfg, PERSON, &["node", "attach", PERSON], None);
    let _daemon = Daemon(data.clone());
    assert!(
        ok,
        "APPARATUS (staging): `vox node attach {PERSON}` (which starts the daemon) failed: {out}{err}"
    );
    staged(&data, &cfg, AGENT, &["node", "attach", AGENT], None);
    let fp = |node: &str| staged(&data, &cfg, node, &["id"], None).trim().to_owned();
    let (person_fp, agent_fp) = (fp(PERSON), fp(AGENT));
    staged(
        &data,
        &cfg,
        PERSON,
        &["room", "create", "--passphrase-file", "-", "--name", "work"],
        Some(&format!("{ROOM_PASS}\n")),
    );
    let list = staged(&data, &cfg, PERSON, &["room", "list"], None);
    let room = list
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("APPARATUS (staging): `vox room list` shows no room: {list:?}"))
        .to_owned();
    let link = staged(&data, &cfg, PERSON, &["room", "link", &room], None)
        .trim()
        .to_owned();
    staged(
        &data,
        &cfg,
        PERSON,
        &["trust", "add", &agent_fp, "--name", AGENT],
        None,
    );
    staged(
        &data,
        &cfg,
        AGENT,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(&format!("{ROOM_PASS}\n")),
    );
    staged(
        &data,
        &cfg,
        AGENT,
        &["trust", "add", &person_fp, "--name", PERSON, "--drive"],
        None,
    );
    // The room map (ADR-029 RB-1): a session started in the work directory works in the room.
    let map = data.join("rooms");
    std::fs::write(
        &map,
        format!(
            "repo {}\n    room       {link}\n    passphrase {ROOM_PASS}\n",
            work.display()
        ),
    )
    .unwrap_or_else(|e| panic!("APPARATUS: cannot write the room map: {e}"));
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&map, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make the room map private: {e}"));
    }

    // ---- Claude Code's config: the plugin's settings, onboarding done, the work dir trusted ----
    let plugin = Command::new(VOX)
        .args(["agent", "plugin", "claude", "--node", AGENT])
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox agent plugin claude: {e}"));
    assert!(
        plugin.status.success(),
        "PRODUCT: `vox agent plugin claude --node {AGENT}` failed"
    );
    let h = ClaudeHome::new(&root, AGENT);
    std::fs::write(h.config.join("settings.json"), &plugin.stdout)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write settings.json: {e}"));
    std::fs::write(
        h.config.join(".claude.json"),
        serde_json::json!({
            "hasCompletedOnboarding": true, "theme": "dark", "numStartups": 5,
            "projects": { work.display().to_string():
                { "hasTrustDialogAccepted": true, "hasCompletedProjectOnboarding": true } },
        })
        .to_string(),
    )
    .unwrap_or_else(|e| panic!("APPARATUS: cannot write .claude.json: {e}"));

    // ---- the sandbox, probed before anything runs under it ----
    let canary = oc_sandbox::Canary::plant();
    let profile = root.join("claude.sb");
    let mut readable: Vec<&Path> = vec![&claude_dir];
    readable.extend(tmux_dirs.iter().map(PathBuf::as_path));
    std::fs::write(&profile, oc_sandbox::sandbox_profile(&[&root], &readable))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write the sandbox profile: {e}"));
    oc_sandbox::probe_profile(&profile, &canary, "claude in tmux");

    if dry_run() {
        println!(
            "[proof] STOPPED BEFORE CLAUDE: nodes, daemon, room {room}, drive, room map, config and \
             the sandbox probes are ready; no sign-in was read and no Claude Code was started"
        );
        return;
    }
    let token = access_token(real_home);

    // ---- the scratch tmux server, confined, its pane a shell in the work directory ----
    let socket = root.join("t.sock");
    let env: Vec<(String, String)> = vec![
        ("PATH".into(), path.clone()),
        ("HOME".into(), h.home.display().to_string()),
        ("TMPDIR".into(), h.tmp.display().to_string()),
        ("CLAUDE_CODE_TMPDIR".into(), h.tmp.display().to_string()),
        ("CLAUDE_CONFIG_DIR".into(), h.config.display().to_string()),
        ("VOX_DATA_DIR".into(), data.display().to_string()),
        ("VOX_CONFIG_DIR".into(), cfg.display().to_string()),
        ("VOX_PROXY".into(), "127.0.0.1:0".into()),
        ("LANG".into(), "en_US.UTF-8".into()),
        ("TERM".into(), "xterm-256color".into()),
        ("CLAUDE_CODE_OAUTH_TOKEN".into(), token.clone()),
    ];
    let tm = |args: &[&str]| -> Command {
        let mut c = Command::new(&tmux);
        c.env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .arg("-S")
            .arg(&socket)
            .arg("-f")
            .arg("/dev/null")
            .args(args);
        c
    };
    let started = Command::new("/usr/bin/sandbox-exec")
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .arg("-f")
        .arg(&profile)
        .arg(&tmux)
        .arg("-S")
        .arg(&socket)
        .args([
            "-f",
            "/dev/null",
            "new-session",
            "-d",
            "-x",
            "160",
            "-y",
            "50",
            "-c",
        ])
        .arg(&work)
        .arg("/bin/sh")
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start the confined tmux server: {e}"));
    assert!(
        started.status.success(),
        "APPARATUS: the confined tmux server did not start: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    struct Server(Command);
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.0.output();
        }
    }
    let _server = Server(tm(&["kill-server"]));
    let pane = String::from_utf8_lossy(
        &tm(&["display-message", "-p", "-t", ":0.0", "#{pane_id}"])
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: tmux: {e}"))
            .stdout,
    )
    .trim()
    .to_owned();
    let screen = || {
        String::from_utf8_lossy(
            &tm(&["capture-pane", "-p", "-t", &pane])
                .output()
                .map(|o| o.stdout)
                .unwrap_or_default(),
        )
        .into_owned()
    };
    // Typed as a person types, and submitted only once it has left Claude Code's input box (the
    // box between its last two rules): an Enter that lands while the TUI is busy is swallowed.
    let in_box = |s: &str, text: &str| {
        let lines: Vec<&str> = s.lines().collect();
        let rules: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.matches('─').count() >= 20)
            .map(|(i, _)| i)
            .collect();
        let tail: String = text
            .chars()
            .skip(text.chars().count().saturating_sub(20))
            .collect();
        match rules[..] {
            [.., top, bottom] => lines[top + 1..bottom].join("").contains(tail.trim()),
            _ => false,
        }
    };
    let type_line = |text: &str| {
        let _ = tm(&["send-keys", "-t", &pane, "-l", text]).output();
        std::thread::sleep(Duration::from_millis(600));
        for _ in 0..5 {
            let _ = tm(&["send-keys", "-t", &pane, "Enter"]).output();
            std::thread::sleep(Duration::from_millis(1500));
            if !in_box(&screen(), text) {
                return;
            }
        }
        panic!(
            "APPARATUS: {text:?} stayed in Claude Code's input box after five Enters:\n{}",
            screen()
        );
    };
    // Never a sign-in or trust screen: one appearing stops the run, nothing typed into it.
    let guard = |s: &str| {
        for bad in [
            "Select login method",
            "API key",
            "Paste code",
            "Log in to",
            "trust this folder",
        ] {
            assert!(
                !s.contains(bad),
                "APPARATUS: Claude Code showed a sign-in or trust screen ({bad:?}); stopped \
                 without typing into it. The pane:\n{s}"
            );
        }
    };
    let wait_screen = |what: &str, within: Duration, pred: &dyn Fn(&str) -> bool| -> String {
        let t0 = Instant::now();
        loop {
            let s = screen();
            guard(&s);
            if pred(&s) {
                return s;
            }
            assert!(
                t0.elapsed() < within,
                "APPARATUS: Claude Code's pane never showed {what} within {within:?}:\n{s}"
            );
            std::thread::sleep(Duration::from_millis(400));
        }
    };

    // ---- Claude Code, interactive, in the pane ----
    type_line(&format!("{} --model {MODEL}", claude.display()));
    wait_screen("its prompt", Duration::from_secs(90), &|s| {
        s.contains("Claude Code v")
            && s.lines().filter(|l| l.matches('─').count() >= 20).count() >= 2
    });
    println!("[proof] Claude Code is up in pane {pane} of the scratch server");

    let session_read = |args: &[&str]| -> (bool, String, String) {
        let mut a = vec!["room", "session", room.as_str()];
        a.extend_from_slice(args);
        vox(&data, &cfg, PERSON, &a, None)
    };
    // ---- 1. followed ----
    let prompt = "Run exactly this bash command and nothing else: touch approved.txt";
    type_line(prompt);
    let t0 = Instant::now();
    let session = loop {
        let (_, o, _) = vox(
            &data,
            &cfg,
            PERSON,
            &["room", "sessions", &room, "--json"],
            None,
        );
        let id = o
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|v| v["harness"] == "claude" && v["open"] == true)
            .and_then(|v| v["id"].as_str().map(str::to_owned));
        if let Some(id) = id {
            break id;
        }
        guard(&screen());
        assert!(
            t0.elapsed() < Duration::from_secs(90),
            "PRODUCT: within 90 s of the prompt, {PERSON} never saw a Claude Code Session listed in \
             the room: {o}"
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    println!("[proof] 1. the Session: {session}");
    // The pane the daemon proved for it, as the session's registration holds it: the hook's
    // TMUX/TMUX_PANE, and the Claude Code process found under it.
    let reg = std::fs::read_to_string(
        data.join("nodes")
            .join(AGENT)
            .join("sessions")
            .join(format!("{session}.json")),
    )
    .unwrap_or_default();
    let reg: serde_json::Value = serde_json::from_str(&reg).unwrap_or_default();
    println!(
        "[proof] 1. its registration: tmux {} / why not {}",
        reg["tmux"], reg["tmux_why"]
    );
    let t0 = Instant::now();
    let (approval_ref, followed) = loop {
        let (_, o, e) = session_read(&[&session, "--json"]);
        let lines: Vec<serde_json::Value> = o
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let pending = lines.iter().find(|v| {
            v["kind"] == "approval"
                && v["line"].as_str().is_some_and(|l| {
                    l.contains("touch approved.txt") && l.ends_with("approve or reject?")
                })
        });
        if let Some(p) = pending {
            break (p["ref"].as_str().unwrap_or_default().to_owned(), o);
        }
        guard(&screen());
        assert!(
            t0.elapsed() < Duration::from_secs(120),
            "PRODUCT: within 120 s, {PERSON}'s Session never showed the approval Claude Code asked \
             for (`touch approved.txt — approve or reject?`); it showed:\n{o}{e}\nthe pane:\n{}",
            screen()
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    println!("[proof] 1. the Session followed the turn:\n{followed}");
    assert!(
        followed.contains(&format!("typed at the terminal: {prompt}")),
        "PRODUCT: 1. the Session must show the prompt typed at the terminal; it showed:\n{followed}"
    );
    let on_screen = screen();
    println!(
        "[proof] 2. Claude Code's own permission prompt is on its screen too: {}",
        on_screen.contains("Do you want")
    );

    // ---- 2. answered from the Session ----
    let (ok, said, err) = session_read(&[&session, "--approve", &approval_ref]);
    println!(
        "[proof] 2. --approve {approval_ref}: {}{}",
        said.trim(),
        err.trim()
    );
    assert!(
        ok,
        "PRODUCT: 2. the approval from the Session must be handed to Claude Code; vox said: {said}{err}"
    );
    let t0 = Instant::now();
    loop {
        let (_, plain, _) = session_read(&[&session]);
        if work.join("approved.txt").exists() && plain.contains("approved here") {
            println!("[proof] 2. approved.txt exists; the Session:\n{plain}");
            break;
        }
        guard(&screen());
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "PRODUCT: 2. within 60 s of the approval from the Session, Claude Code must run the call \
             (approved.txt exists: {}) and the Session read \"approved here\"; it read:\n{plain}\nthe \
             pane:\n{}",
            work.join("approved.txt").exists(),
            screen()
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    // ---- 3. interrupted from the Session ----
    let story = "Write a 600-word story about a lighthouse keeper. Do not use any tools.";
    type_line(story);
    // The reply is under way once the Session shows the prompt (its hook ran) and a moment passed.
    let t0 = Instant::now();
    loop {
        let (_, plain, _) = session_read(&[&session]);
        if plain.contains("typed at the terminal: Write a 600-word story") {
            break;
        }
        guard(&screen());
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "PRODUCT: 3. the Session never showed the second prompt typed at the terminal:\n{plain}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    std::thread::sleep(Duration::from_secs(2));
    let (ok, said, err) = session_read(&[&session, "--interrupt"]);
    println!("[proof] 3. --interrupt: {}{}", said.trim(), err.trim());
    assert!(
        ok,
        "PRODUCT: 3. the interrupt from the Session must be delivered to its terminal; vox said: \
         {said}{err}"
    );
    let stopped = wait_screen("the interruption", Duration::from_secs(20), &|s| {
        s.contains("Interrupted")
    });
    println!(
        "[proof] 3. the pane after the interrupt says: {}",
        stopped
            .lines()
            .find(|l| l.contains("Interrupted"))
            .unwrap_or_default()
            .trim()
    );

    // ---- leave: Claude Code's own exit, then the server ----
    type_line("/exit");
    std::thread::sleep(Duration::from_secs(3));
    let (files, holding) = files_holding(&root, &[&token, &canary.text]);
    drop(token);
    println!(
        "[proof] every file the run left under its root ({files} files) searched for the token and \
         the canary: {} hold either",
        holding.len()
    );
    assert!(
        holding.is_empty(),
        "APPARATUS: the sign-in token or the canary was written to {holding:?} under the run's root"
    );
}
