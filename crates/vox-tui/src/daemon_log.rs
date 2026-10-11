//! The daemon's own bounded, counted log (ADR-034 LG-1–LG-2).
//!
//! Capture both output streams so diagnostics from core and subprocesses also have a UTC
//! timestamp. A repeated line updates its fixed-width count in place; it consumes no more
//! disk. Rotation bounds the current file and its one predecessor to one MiB each.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LIMIT: u64 = 1024 * 1024;
const LINE_LIMIT: usize = 16 * 1024;

struct Log {
    path: PathBuf,
    file: File,
    len: u64,
    counts: HashMap<String, (u64, u64)>,
}

impl Log {
    fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        let len = file.metadata()?.len();
        let mut log = Self {
            path: path.into(),
            file,
            len,
            counts: HashMap::new(),
        };
        // Old versions wrote an unbounded file. Do not keep that oversized predecessor.
        if len > LIMIT {
            log.file.set_len(0)?;
            log.len = 0;
        }
        let previous = path.with_extension("log.1");
        if std::fs::metadata(&previous).is_ok_and(|m| m.len() > LIMIT) {
            std::fs::remove_file(previous)?;
        }
        Ok(log)
    }

    fn line(&mut self, bytes: &[u8]) -> io::Result<()> {
        let line = String::from_utf8_lossy(bytes);
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return Ok(());
        }
        if let Some((at, count)) = self.counts.get_mut(line) {
            *count = count.saturating_add(1);
            self.file.seek(SeekFrom::Start(*at))?;
            write!(self.file, "{count:020}")?;
            return Ok(());
        }
        let prefix = format!("{} {line} [count=", utc_now());
        let record = format!("{prefix}{:020}]\n", 1);
        if self.len + record.len() as u64 > LIMIT {
            // The open descriptor can be renamed on both supported Unix platforms.
            std::fs::rename(&self.path, self.path.with_extension("log.1"))?;
            self.file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(&self.path)?;
            self.len = 0;
            self.counts.clear();
        }
        self.file.seek(SeekFrom::Start(self.len))?;
        self.file.write_all(record.as_bytes())?;
        self.counts
            .insert(line.to_owned(), (self.len + prefix.len() as u64, 1));
        self.len += record.len() as u64;
        Ok(())
    }
}

/// Installed only after the account lock is held, before any node starts.
pub(crate) struct Capture {
    stdout: File,
    stderr: File,
    stop: Arc<AtomicBool>,
    readers: Vec<std::thread::JoinHandle<()>>,
}

impl Capture {
    pub(crate) fn start(path: &Path, foreground: bool) -> io::Result<Self> {
        let log = Arc::new(Mutex::new(Log::open(path)?));
        let stdout = File::from(nix::unistd::dup(io::stdout())?);
        let stderr = File::from(nix::unistd::dup(io::stderr())?);
        let (out_read, out_write) = UnixStream::pair()?;
        let (err_read, err_write) = UnixStream::pair()?;
        let stop = Arc::new(AtomicBool::new(false));
        let mut capture = Self {
            stdout,
            stderr,
            stop,
            readers: Vec::new(),
        };
        for (mut input, original) in [(out_read, &capture.stdout), (err_read, &capture.stderr)] {
            input.set_read_timeout(Some(Duration::from_millis(100)))?;
            let mut terminal = foreground.then(|| original.try_clone()).transpose()?;
            let log = log.clone();
            let stop = capture.stop.clone();
            let reader = std::thread::Builder::new()
                .name("vox-daemon-log".into())
                .spawn(move || {
                    let mut buf = [0; 4096];
                    let mut line = Vec::new();
                    loop {
                        match input.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                // Prompts need not end in a newline; the terminal sees them at once.
                                if let Some(terminal) = terminal.as_mut() {
                                    let _ = terminal.write_all(&buf[..n]);
                                    let _ = terminal.flush();
                                }
                                for &byte in &buf[..n] {
                                    line.push(byte);
                                    if byte == b'\n' || line.len() >= LINE_LIMIT {
                                        if let Ok(mut log) = log.lock() {
                                            let _ = log.line(&line);
                                        }
                                        line.clear();
                                    }
                                }
                            }
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                ) =>
                            {
                                if stop.load(Ordering::Relaxed) {
                                    break;
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                            Err(_) => break,
                        }
                    }
                    if !line.is_empty() {
                        if let Ok(mut log) = log.lock() {
                            let _ = log.line(&line);
                        }
                    }
                })?;
            capture.readers.push(reader);
        }
        io::stdout().flush()?;
        io::stderr().flush()?;
        nix::unistd::dup2_stdout(&out_write)?;
        nix::unistd::dup2_stderr(&err_write)?;
        Ok(capture)
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();
        let _ = nix::unistd::dup2_stdout(&self.stdout);
        let _ = nix::unistd::dup2_stderr(&self.stderr);
        self.stop.store(true, Ordering::Relaxed);
        // An inherited child descriptor cannot keep a reader waiting after the daemon stops.
        let until = std::time::Instant::now() + Duration::from_millis(250);
        while self.readers.iter().any(|r| !r.is_finished()) && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
        for reader in self.readers.drain(..) {
            if reader.is_finished() {
                let _ = reader.join();
            }
        }
    }
}

fn utc_now() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = elapsed.as_secs();
    // Gregorian civil date from days since 1970-01-01; no local timezone is consulted.
    let z = (seconds / 86400) as i64 + 719468;
    let era = z.div_euclid(146097);
    let day = z - era * 146097;
    let year_in_era = (day - day / 1460 + day / 36524 - day / 146096) / 365;
    let mut year = year_in_era + era * 400;
    let day_of_year = day - (365 * year_in_era + year_in_era / 4 - year_in_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let date = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{date:02}T{:02}:{:02}:{:02}.{:03}Z",
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60,
        elapsed.subsec_millis()
    )
}
