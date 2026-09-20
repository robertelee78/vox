//! The broadcast (one-to-many) group message: header, AEAD ciphertext under the
//! per-iteration message key, and a composite signature by the Sender-Key signing
//! key (ADR-006 §Wire).
//!
//! ## Header (ADR-006 §Wire, exact fields)
//! `{ channelID, epoch, author_id, chain_id, iteration }` — all five are bound
//! into the AEAD associated data ([`crate::group::wire::GROUP_MSG_AD_DOMAIN`]) so
//! a receiver rejects any message whose `(channelID, epoch)` (or any other header
//! field) does not match what it authenticated. This is the cross-group-confusion
//! guard (eprint 2023/1385): a ciphertext produced for channel G cannot open in
//! channel H because the AD differs, and the AEAD tag will not verify.
//!
//! ## Signature
//! Beyond the AEAD (which proves the holder of the message key produced the
//! ciphertext), each message carries a composite signature by the sender's
//! Sender-Key **signing** key over `GROUP_MSG_SIGN_DOMAIN ‖ header ‖ ciphertext`.
//! Because that signing key is root-cross-signed (the SKDM), the signature ties
//! authorship to the sender's identity — a recipient who holds the chain key
//! could otherwise forge a message under it, so the signature is what makes
//! broadcast authorship non-repudiable to other members.
//!
//! ## AEAD
//! AES-256-GCM under the per-iteration message key, with a deterministic nonce
//! derived from that key. Each message key is used exactly once (the chain
//! ratchets one step per message and the key is deleted after use), so the
//! `(key, nonce)` pair never repeats — the same single-use discipline the M2
//! ratchet relies on.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::group::senderkey::{MessageKey, SenderKeySigningKey};
use crate::group::wire::{domain_prefixed, GROUP_MSG_AD_DOMAIN, GROUP_MSG_SIGN_DOMAIN};
use crate::hash::Digest32;
use crate::identity::composite::{CompositePublicKey, CompositeSignature};

type HmacSha256 = Hmac<Sha256>;

/// A broadcast-message header (ADR-006 §Wire). Transmitted in the clear (it
/// routes which chain/iteration to derive) but bound into the AEAD AD and the
/// signature, so tampering any field fails decryption and verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageHeader {
    /// The 32-byte channel identifier.
    pub channel_id: Digest32,
    /// The membership epoch (ADR-007).
    pub epoch: u64,
    /// The author's identity fingerprint (ADR-002).
    pub author_id: Digest32,
    /// The sender-key generation id (ADR-006).
    pub chain_id: u64,
    /// The message's iteration in that chain.
    pub iteration: u64,
}

impl MessageHeader {
    /// Canonical-CBOR body, fixed order
    /// `[channelID, epoch, author_id, chain_id, iteration]` (ADR-008 array).
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(5)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.author_id)
            .uint(self.chain_id)
            .uint(self.iteration);
        e.finish()
    }

    /// Decode a header from its canonical body, rejecting the wrong arity or a
    /// bad digest length.
    pub fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 5 {
            return Err(Error::MalformedBundle("group header arity"));
        }
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        let author_id = take_digest(&mut d)?;
        let chain_id = d.uint()?;
        let iteration = d.uint()?;
        d.finish()?;
        Ok(Self {
            channel_id,
            epoch,
            author_id,
            chain_id,
            iteration,
        })
    }

    /// The AEAD associated data binding this header to its channel/epoch/author/
    /// generation/iteration: `GROUP_MSG_AD_DOMAIN ‖ header_body`.
    #[must_use]
    pub fn associated_data(&self) -> Vec<u8> {
        Self::associated_data_from(&self.canonical_body())
    }

    /// The AEAD associated data given the header's already-computed canonical
    /// body, so callers that also need the body for the nonce derivation compute
    /// it once: `GROUP_MSG_AD_DOMAIN ‖ header_body`.
    #[must_use]
    fn associated_data_from(header_body: &[u8]) -> Vec<u8> {
        domain_prefixed(GROUP_MSG_AD_DOMAIN, header_body)
    }
}

/// A broadcast group message on the wire (ADR-006 §Wire): the cleartext header,
/// the AEAD ciphertext, and the composite Sender-Key signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMessage {
    /// The cleartext, AD-bound header.
    pub header: MessageHeader,
    /// AES-256-GCM ciphertext (`ciphertext ‖ 16-byte tag`).
    pub ciphertext: Vec<u8>,
    /// Composite signature by the Sender-Key signing key over
    /// `GROUP_MSG_SIGN_DOMAIN ‖ header_body ‖ ciphertext`.
    pub signature: CompositeSignature,
}

impl GroupMessage {
    /// Encrypt `plaintext` under `message_key` for `header`, then sign the result
    /// with the Sender-Key `signing_key`.
    ///
    /// The header's `author_id`/`chain_id`/`iteration`/`(channelID, epoch)` MUST
    /// be the values that produced `message_key`; the caller (the send-side
    /// [`crate::group::state::SenderChain`]) guarantees this.
    ///
    /// `pub(crate)`: only [`crate::group::state::SenderChain`] may seal a message,
    /// so the one-message-key-per-AEAD-nonce invariant cannot be violated by an
    /// external caller reusing a key under a different header (the nonce is bound
    /// to the header as defense in depth, but the entry point is still gated).
    pub(crate) fn seal(
        header: MessageHeader,
        message_key: &MessageKey,
        signing_key: &SenderKeySigningKey,
        plaintext: &[u8],
    ) -> Result<Self> {
        let header_body = header.canonical_body();
        let ad = MessageHeader::associated_data_from(&header_body);
        let ciphertext = aead_seal(message_key, &header_body, &ad, plaintext)?;
        let signature = signing_key.sign(&Self::sign_input(&header, &ciphertext))?;
        Ok(Self {
            header,
            ciphertext,
            signature,
        })
    }

    /// Verify the composite signature against `signing_pubkey`, then AEAD-decrypt
    /// under `message_key`. Both the signature and the AEAD bind the full header,
    /// so any header/ciphertext tamper fails. Returns the plaintext on success.
    ///
    /// `pub(crate)`: only [`crate::group::state::ReceiverChain`] drives decryption,
    /// matching [`GroupMessage::seal`].
    pub(crate) fn open(
        &self,
        message_key: &MessageKey,
        signing_pubkey: &CompositePublicKey,
    ) -> Result<Vec<u8>> {
        // Verify authorship FIRST (cheap rejection of forged-but-well-formed
        // packets is fine; the AEAD then proves the message-key holder).
        signing_pubkey.verify(
            &Self::sign_input(&self.header, &self.ciphertext),
            &self.signature,
        )?;
        let header_body = self.header.canonical_body();
        let ad = MessageHeader::associated_data_from(&header_body);
        aead_open(message_key, &header_body, &ad, &self.ciphertext)
    }

    /// The composite-signature input: `GROUP_MSG_SIGN_DOMAIN ‖ header_body ‖
    /// ciphertext`. Covering the ciphertext (not the plaintext) lets a recipient
    /// verify authorship before decrypting.
    fn sign_input(header: &MessageHeader, ciphertext: &[u8]) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2).bytes(&header.canonical_body()).bytes(ciphertext);
        domain_prefixed(GROUP_MSG_SIGN_DOMAIN, &e.finish())
    }

    /// Canonical-CBOR body for wire transport: `[header_body, ciphertext, sig]`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3)
            .bytes(&self.header.canonical_body())
            .bytes(&self.ciphertext)
            .bytes(&self.signature.to_bytes());
        e.finish()
    }

    /// Frame for the wire under [`GROUP_MSG_SIGN_DOMAIN`].
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        domain_prefixed(GROUP_MSG_SIGN_DOMAIN, &self.canonical_body())
    }

    /// Parse a wire-framed group message, rejecting a wrong domain label, arity,
    /// or malformed signature.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let body = bytes
            .strip_prefix(GROUP_MSG_SIGN_DOMAIN.as_bytes())
            .ok_or(Error::MalformedBundle("group-msg domain label"))?;
        let mut d = Decoder::new(body);
        if d.array()? != 3 {
            return Err(Error::MalformedBundle("group-msg arity"));
        }
        let header = MessageHeader::from_canonical_body(d.bytes()?)?;
        let ciphertext = d.bytes()?.to_vec();
        let sig_bytes = d.bytes()?;
        let sig_arr: [u8; crate::hash::COMPOSITE_SIG_LEN] = sig_bytes
            .try_into()
            .map_err(|_| Error::MalformedBundle("group-msg signature length"))?;
        let signature = CompositeSignature::from_bytes(&sig_arr)?;
        d.finish()?;
        Ok(Self {
            header,
            ciphertext,
            signature,
        })
    }
}

/// AES-256-GCM seal under a single-use message key with a nonce derived from the
/// key AND the canonical header bytes.
fn aead_seal(mk: &MessageKey, header_body: &[u8], ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(mk.bytes())
        .map_err(|_| Error::MalformedBundle("group aead key"))?;
    let nonce = message_nonce(mk, header_body)?;
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .map_err(|_| Error::MalformedBundle("group aead seal"))
}

/// AES-256-GCM open; any authentication failure is [`Error::SignatureInvalid`].
fn aead_open(mk: &MessageKey, header_body: &[u8], ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(mk.bytes())
        .map_err(|_| Error::MalformedBundle("group aead key"))?;
    let nonce = message_nonce(mk, header_body)?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| Error::SignatureInvalid)
}

/// Derive a deterministic 96-bit AEAD nonce from the single-use message key
/// **and** the canonical header bytes: `HMAC(mk, 0x03 ‖ header_body)[..12]`.
///
/// Binding the header (which carries `channelID, epoch, author_id, chain_id,
/// iteration`) means that even if the same message key were ever presented under
/// a *different* header — e.g. via misuse of a low-level seal — the nonce would
/// differ, so a `(key, nonce)` collision cannot occur. In normal operation each
/// message key is single-use anyway (the chain ratchets one step per message and
/// the key is dropped after use, the M2-ratchet rule); this is defense in depth.
fn message_nonce(mk: &MessageKey, header_body: &[u8]) -> Result<[u8; 12]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(mk.bytes())
        .map_err(|_| Error::MalformedBundle("group nonce kdf"))?;
    mac.update(&[0x03]);
    mac.update(header_body);
    let tag = mac.finalize().into_bytes();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&tag[..12]);
    Ok(nonce)
}

/// Take a 32-byte digest from the decoder, rejecting a wrong length.
fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle("group digest length"))
}
