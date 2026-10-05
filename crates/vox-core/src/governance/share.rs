//! The **service share** (tag `0x0018`, domain `vox/service-share/v1`): a member's own signed word
//! that it shares a named service with the room, or no longer does (V030-25, ADR-017 decision 12).
//!
//! A node shares a service with a room, and the service is reached as
//! `<service>.<node>.<room>.vox` and only that way. The name is the sharing node's: it is what the
//! host's own gate looks the service up by, so it carries no authority and grants nothing. Who
//! reaches it is still the host's decision alone (its trust keyring and the room's current
//! authors). The statement exists so every member can **list** what is shared in its rooms and who
//! shared it, from the log, without asking anyone.
//!
//! Only the member itself can make the statement: the body names its author, and the log entry
//! that carries it is signed by that author. The last statement an author made about a name wins.
//!
//! Body: `{ channelID, epoch, author_id, name, udp, shared, kind }`. The kind is what the sharing
//! node detected the service to be (ADR-028 S-2), never what its sharer typed.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// The longest service name: one DNS label.
pub const MAX_SERVICE_NAME: usize = 63;

/// A service's **fingerprint**: what `<service>` may be instead of its name, as a node or a room
/// may be its fingerprint instead of an alias. It commits to the room, the sharing node and the
/// name, so it names one service and no other.
#[must_use]
pub fn service_fingerprint(channel_id: &Digest32, host: &Digest32, name: &str) -> Digest32 {
    let mut input = Vec::with_capacity(32 + 32 + 32 + name.len());
    input.extend_from_slice(b"vox/service-fingerprint/v1");
    input.extend_from_slice(channel_id);
    input.extend_from_slice(host);
    input.extend_from_slice(name.as_bytes());
    sha256(&input)
}

/// What a shared service is, as its sharing node detected it (ADR-028 S-2): from the listening
/// process and a probe for an endpoint on that machine, from a probe on the wire for one on
/// another. Never from the port number or the service's name. Anything not identified is plain
/// [`ServiceKind::Tcp`] or [`ServiceKind::Udp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    /// A byte stream nothing identified.
    Tcp,
    /// Datagrams nothing identified.
    Udp,
    /// An SSH server: it sent an `SSH-` banner.
    Ssh,
    /// An HTTP server: it answered a request with `HTTP/`.
    Http,
    /// A TLS server: it answered a ClientHello.
    Https,
    /// A DNS server: it answered a query.
    Dns,
}

impl ServiceKind {
    /// Its word, as the statement carries it and a person reads it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Ssh => "ssh",
            Self::Http => "http",
            Self::Https => "https",
            Self::Dns => "dns",
        }
    }

    /// The kind its word names, or `None` for any other word.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        Some(match word {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "ssh" => Self::Ssh,
            "http" => Self::Http,
            "https" => Self::Https,
            "dns" => Self::Dns,
            _ => return None,
        })
    }

    /// The kind of a service nothing identified.
    #[must_use]
    pub fn plain(udp: bool) -> Self {
        if udp {
            Self::Udp
        } else {
            Self::Tcp
        }
    }

    /// Whether a service of this kind can be carried as datagrams (`udp`) or as a byte stream.
    #[must_use]
    pub fn fits(self, udp: bool) -> bool {
        match self {
            Self::Tcp | Self::Ssh | Self::Http | Self::Https => !udp,
            Self::Udp => udp,
            Self::Dns => true,
        }
    }
}

impl std::fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The unsigned share body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceShareBody {
    /// The room.
    pub channel_id: Digest32,
    /// The membership epoch the statement is made in.
    pub epoch: u64,
    /// The member sharing (or withdrawing) the service.
    pub author_id: Digest32,
    /// The service's name, as its sharer gave it: one DNS label.
    pub name: String,
    /// Whether it carries datagrams (ADR-022) rather than a byte stream.
    pub udp: bool,
    /// `true`: shared. `false`: no longer shared.
    pub shared: bool,
    /// What the service is, as its sharing node detected it (ADR-028 S-2).
    pub kind: ServiceKind,
}

impl ServiceShareBody {
    /// Canonical-CBOR body `[channelID, epoch, author_id, name, udp, shared, kind]`, flags as 0
    /// or 1, the kind as its word.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(7)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.author_id)
            .text(&self.name)
            .uint(u64::from(self.udp))
            .uint(u64::from(self.shared))
            .text(self.kind.as_str());
        e.finish()
    }

    /// The signing input: `vox/service-share/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::ServiceShare, &self.canonical_body())
    }
}

/// A complete, root-signed share statement.
#[derive(Debug, Clone)]
pub struct ServiceShare {
    /// The signed body.
    pub body: ServiceShareBody,
    /// The member's composite root signature.
    pub signature: CompositeSignature,
}

impl ServiceShare {
    /// Build and root-sign `author_root`'s statement that it shares `name` in `channel_id`, or no
    /// longer does.
    pub fn build(
        author_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        name: &str,
        udp: bool,
        shared: bool,
        kind: ServiceKind,
    ) -> Result<Self> {
        check_name(name)?;
        if !kind.fits(udp) {
            return Err(Error::MalformedGovernance("service share kind"));
        }
        let body = ServiceShareBody {
            channel_id: *channel_id,
            epoch,
            author_id: author_root.fingerprint(),
            name: name.to_owned(),
            udp,
            shared,
            kind,
        };
        let signature = author_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Frame for the wire/storage (tag `0x0018`): body fields then the signature.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let b = &self.body;
        let mut e = Encoder::new();
        e.array(8)
            .bytes(&b.channel_id)
            .uint(b.epoch)
            .bytes(&b.author_id)
            .text(&b.name)
            .uint(u64::from(b.udp))
            .uint(u64::from(b.shared))
            .text(b.kind.as_str())
            .bytes(&self.signature.to_bytes());
        frame(StructTag::ServiceShare, &e.finish())
    }

    /// Parse a framed share statement (does NOT verify).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::ServiceShare {
            return Err(Error::MalformedGovernance("service share wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 8 {
            return Err(Error::MalformedGovernance("service share wire arity"));
        }
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        let author_id = take_digest(&mut d)?;
        let name = d.text()?.to_owned();
        check_name(&name)?;
        let udp = flag(d.uint()?)?;
        let shared = flag(d.uint()?)?;
        let kind = ServiceKind::from_word(d.text()?)
            .filter(|k| k.fits(udp))
            .ok_or(Error::MalformedGovernance("service share kind"))?;
        let sig: [u8; COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedGovernance("service share sig length"))?;
        d.finish()?;
        Ok(Self {
            body: ServiceShareBody {
                channel_id,
                epoch,
                author_id,
                name,
                udp,
                shared,
                kind,
            },
            signature: CompositeSignature::from_bytes(&sig)?,
        })
    }

    /// Verify the signature and that `author_id` is the signer.
    pub fn verify(&self, author_root: &CompositePublicKey) -> Result<()> {
        if author_root.fingerprint() != self.body.author_id {
            return Err(Error::MalformedGovernance(
                "service share author_id != signer fingerprint",
            ));
        }
        author_root.verify(&self.body.signing_input(), &self.signature)
    }
}

/// A name is one DNS label: lowercase letters, digits and inner `-`, at most
/// [`MAX_SERVICE_NAME`] characters. Anything else could not be typed as the first part of a
/// `.vox` address.
fn check_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= MAX_SERVICE_NAME
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(Error::MalformedGovernance(
            "service share name is not a DNS label",
        ))
    }
}

fn flag(v: u64) -> Result<bool> {
    match v {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::MalformedGovernance("service share flag")),
    }
}

fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("service share digest length"))
}
