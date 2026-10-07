//! `vox lan up` through the daemon (ADR-026 S-5): what a node's connection asks of its daemon to
//! run a room's family LAN, and the lines the daemon answers with. The LAN lives exactly as long
//! as that connection. `vox lan up` and the macOS app both speak it; the daemon serves it.
//!
//! The request is `[T_LAN_UP, room, helper socket, stats file or "", allowed ports as "p,p"]`; each
//! answer is `[T_LAN_SAID, text]`, a line for the person, or `[T_LAN_FAILED, text]`, after which
//! the connection closes. Tags away from every IPC range.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::cbor::{Decoder, Encoder};
use crate::hash::Digest32;

/// Where the root helper listens unless told otherwise (ADR-013; ADR-014 M-10).
pub const DEFAULT_HELPER_SOCKET: &str = "/var/run/vox-lan.sock";

/// The request.
pub const T_LAN_UP: u64 = 4600;
/// The daemon's line for the person.
pub const T_LAN_SAID: u64 = 4601;
/// The LAN could not start, and why; the connection then closes.
pub const T_LAN_FAILED: u64 = 4602;

/// What `vox lan up` asks of the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanRequest {
    /// The room.
    pub channel_id: Digest32,
    /// The root helper's socket, absolute.
    pub helper: PathBuf,
    /// Where the LAN writes its counters, absolute; `None` for nowhere.
    pub stats_file: Option<PathBuf>,
    /// The ports the LAN carries besides discovery; empty for every port.
    pub allow: BTreeSet<u16>,
}

impl LanRequest {
    /// The request's body (unframed).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let allow: Vec<String> = self.allow.iter().map(u16::to_string).collect();
        let mut e = Encoder::new();
        e.array(5)
            .uint(T_LAN_UP)
            .bytes(&self.channel_id)
            .text(&self.helper.to_string_lossy())
            .text(
                &self
                    .stats_file
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            )
            .text(&allow.join(","));
        e.finish()
    }

    /// Whether `body` is a LAN request, read no further.
    #[must_use]
    pub fn claims(body: &[u8]) -> bool {
        let mut d = Decoder::new(body);
        matches!((d.array(), d.uint()), (Ok(5), Ok(T_LAN_UP)))
    }

    /// The request in `body`, or `None` when it is not one.
    #[must_use]
    pub fn parse(body: &[u8]) -> Option<Self> {
        let mut d = Decoder::new(body);
        let (Ok(5), Ok(T_LAN_UP)) = (d.array(), d.uint()) else {
            return None;
        };
        let channel_id = Digest32::try_from(d.bytes().ok()?).ok()?;
        let helper = PathBuf::from(d.text().ok()?);
        let stats = d.text().ok()?;
        let allow = d
            .text()
            .ok()?
            .split(',')
            .filter(|p| !p.is_empty())
            .map(str::parse)
            .collect::<Result<_, _>>()
            .ok()?;
        d.finish().ok()?;
        Some(Self {
            channel_id,
            helper,
            stats_file: (!stats.is_empty()).then(|| PathBuf::from(stats)),
            allow,
        })
    }
}

/// What the daemon said on a LAN's connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LanSaid {
    /// A line for the person.
    Said(String),
    /// The LAN could not start, and why.
    Failed(String),
}

impl LanSaid {
    /// One answer, framed as every control-socket frame is (length-prefixed).
    #[must_use]
    pub fn framed(&self) -> Vec<u8> {
        let (tag, text) = match self {
            LanSaid::Said(t) => (T_LAN_SAID, t),
            LanSaid::Failed(t) => (T_LAN_FAILED, t),
        };
        let mut e = Encoder::new();
        e.array(2).uint(tag).text(text);
        let body = e.finish();
        let mut framed = u32::try_from(body.len())
            .unwrap_or(0)
            .to_be_bytes()
            .to_vec();
        framed.extend_from_slice(&body);
        framed
    }

    /// The answer in `body`, or `None` when it is not one (an error frame, say).
    #[must_use]
    pub fn parse(body: &[u8]) -> Option<Self> {
        let mut d = Decoder::new(body);
        match (d.array(), d.uint(), d.text()) {
            (Ok(2), Ok(T_LAN_SAID), Ok(line)) => Some(LanSaid::Said(line.to_owned())),
            (Ok(2), Ok(T_LAN_FAILED), Ok(why)) => Some(LanSaid::Failed(why.to_owned())),
            _ => None,
        }
    }
}
