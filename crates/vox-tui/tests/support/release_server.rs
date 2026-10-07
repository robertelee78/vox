//! A loopback release server: python's `http.server` over a directory laid out like a GitHub
//! release (`releases/latest/download/<record>`, `releases/download/v<version>/<asset>`). The
//! proofs point `install.sh` (`VOX_RELEASE_BASE`) and a test-knobs `vox update`
//! (`VOX_TEST_RELEASE_BASE`) at it, which is how a refusal that needs a broken release is proved.

use std::path::Path;
use std::process::{Child, Command, Stdio};

/// A python `http.server` over `root`, on a port it chose itself. Killed on drop.
pub struct Server {
    child: Child,
    pub base: String,
    /// Everything python said: its request log is on stderr.
    log: std::sync::Arc<std::sync::Mutex<String>>,
}

impl Server {
    /// How many requests the server has answered so far.
    pub fn requests(&self) -> usize {
        self.log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .matches("\"GET ")
            .count()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// How long python may take to start serving.
///
/// `python3` is whatever is on `PATH`, often a version-manager shim that runs several processes
/// before python itself. This used to allow 5s, and on a loaded box (load 81) the proof failed in
/// 9s with "the loopback release server never came up" while nothing was wrong with `install.sh`
/// (#164). A python started 6s late reproduces that failure every time.
const SERVER_START: std::time::Duration = std::time::Duration::from_secs(90);

/// Serve `root` over loopback HTTP.
///
/// **python picks the port and says which.** This used to reserve a port by binding and
/// releasing it, start python on it, and take "the port is bound now" as "python is serving". That
/// was a race: anything that took the port in between made the check pass against the wrong
/// server, and a python that failed to start left only a timeout, because its stderr went to
/// `/dev/null`. Now python binds port 0 and prints the port it got, which is the one fact that
/// means it is serving; and if it exits instead, the failure carries its exit status and stderr.
pub fn serve(root: &Path) -> Result<Server, String> {
    use std::io::{BufRead as _, BufReader, Read as _};
    let mut child = Command::new("python3")
        .args([
            "-u",
            "-m",
            "http.server",
            "0",
            "--bind",
            "127.0.0.1",
            "--directory",
        ])
        .arg(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("python3 could not be run ({e}); it is what serves the release"))?;
    // Both pipes are drained for the server's whole life: its request log goes to stderr, and an
    // undrained pipe would stop it mid-proof once full.
    let said = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "python3 has no stderr pipe".to_owned())?;
    let err_log = std::sync::Arc::clone(&said);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stderr.read(&mut buf) {
            if n == 0 {
                break;
            }
            err_log
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "python3 has no stdout pipe".to_owned())?;
    let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();
    let out_log = std::sync::Arc::clone(&said);
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            // "Serving HTTP on 127.0.0.1 port 61866 (http://127.0.0.1:61866/) ..."
            if let Some(port) = line
                .split_once(" port ")
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .and_then(|p| p.parse().ok())
            {
                let _ = port_tx.send(port);
            }
            out_log
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push_str(&format!("{line}\n"));
        }
    });
    let started = std::time::Instant::now();
    loop {
        if let Ok(port) = port_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            let base = format!("http://127.0.0.1:{port}/releases");
            return Ok(Server {
                child,
                base,
                log: said,
            });
        }
        if let Ok(Some(status)) = child.try_wait() {
            // Let the reader threads take what it said before it went.
            std::thread::sleep(std::time::Duration::from_millis(200));
            return Err(format!(
                "python3 exited ({status}) after {:.1}s without serving; it said: {:?}",
                started.elapsed().as_secs_f64(),
                said.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            ));
        }
        if started.elapsed() > SERVER_START {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "python3 did not start serving within {}s; it said: {:?}",
                SERVER_START.as_secs(),
                said.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            ));
        }
    }
}
