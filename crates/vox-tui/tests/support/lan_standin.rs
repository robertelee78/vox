//! The root helper's piece, answered by a test (apparatus): the helper's protocol on its socket,
//! and one end of a datagram socket pair handed over for a `utun`, framed as a `utun` frames
//! packets. `vox lan up`, or Vox.app's `VoxClient.lan_up`, takes it as the interface; the test
//! holds the other end. The real helper and a real `utun` are `scripts/family-lan-proof.sh`.

#![allow(dead_code)]

use std::io::{BufRead as _, BufReader, IoSlice, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::AsFd as _;
use std::os::unix::net::{UnixDatagram, UnixListener};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};

/// `AF_INET` and `AF_INET6` as a `utun` frames them.
const AF_INET: u32 = 2;
const AF_INET6: u32 = 30;

/// The operating system's side of one member's interface.
#[derive(Clone, Default)]
pub struct Os {
    /// The end the current `vox lan up` does not hold; replaced when it asks again.
    end: Arc<Mutex<Option<UnixDatagram>>>,
    /// Every packet the LAN delivered to this "operating system".
    pub got: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Every request line `vox lan up` sent the helper.
    pub asked: Arc<Mutex<Vec<String>>>,
}

impl Os {
    /// Answer on `socket` as `sudo vox lan helper` does, for as long as the test runs.
    pub fn serve(&self, socket: &Path) {
        let listener = UnixListener::bind(socket).expect("bind the helper socket");
        let me = self.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut line = String::new();
                if BufReader::new(&stream).read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                // `vox lan up` first asks whether a helper is there, and the helper
                // answers with its name and protocol (`lan_cli::helper_answers`).
                if line.trim() == "hello" {
                    let _ = (&stream).write_all(b"vox lan helper 1\n");
                    continue;
                }
                me.asked.lock().unwrap().push(line.trim().to_owned());
                let (theirs, ours) = UnixDatagram::pair().expect("socket pair");
                for s in [&theirs, &ours] {
                    let _ = rustix::net::sockopt::set_socket_send_buffer_size(s, 1 << 20);
                    let _ = rustix::net::sockopt::set_socket_recv_buffer_size(s, 4 << 20);
                }
                let fds = [theirs.as_fd()];
                let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
                let mut control = SendAncillaryBuffer::new(&mut space);
                assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
                rustix::net::sendmsg(
                    &stream,
                    &[IoSlice::new(b"ok utun-standin\n")],
                    &mut control,
                    SendFlags::empty(),
                )
                .expect("hand the descriptor over");
                // As the helper does: hold our copy until `vox lan up` has its own
                // (it closes the connection). Dropped while in flight, macOS's
                // collector for descriptors in flight flushes it, and every write
                // into the interface fails with EINVAL.
                let _ = std::io::Read::read(&mut &stream, &mut [0u8; 1]);
                drop(theirs);
                let reader = ours.try_clone().expect("clone");
                *me.end.lock().unwrap() = Some(ours);
                let sink = Arc::clone(&me.got);
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 4 + 65_535];
                    while let Ok(n) = reader.recv(&mut buf) {
                        if n == 0 {
                            return;
                        }
                        if n > 4 {
                            sink.lock().unwrap().push(buf[4..n].to_vec());
                        }
                    }
                });
            }
        });
    }

    /// The operating system sends `p` out of the interface.
    pub fn emit(&self, p: &[u8]) {
        let family = if p[0] >> 4 == 6 { AF_INET6 } else { AF_INET };
        let mut framed = family.to_be_bytes().to_vec();
        framed.extend_from_slice(p);
        let guard = self.end.lock().unwrap();
        let end = guard.as_ref().expect("no interface was handed over");
        loop {
            match end.send(&framed) {
                Ok(_) => return,
                // The LAN has not read the last ones yet: wait, as a full queue would.
                Err(e)
                    if e.raw_os_error() == Some(rustix::io::Errno::NOBUFS.raw_os_error())
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("writing into the interface: {e}"),
            }
        }
    }
}
