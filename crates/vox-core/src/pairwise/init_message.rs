//! The PQXDH initial message wire struct (ADR-004 §Wire).
//!
//! Split out of [`crate::pairwise::pqxdh`] so the handshake math and the wire
//! serialization stay individually small and auditable. The message is a
//! canonical-CBOR body under [`PQXDH_INIT_DOMAIN`] — a *payload* carried by later
//! milestones, not an ADR-008 log struct (see the module docs of
//! [`crate::pairwise::header`] for that boundary).

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::identity::keyagreement::X25519_PUB_LEN;
use crate::pairwise::header::PQXDH_INIT_DOMAIN;
use crate::pairwise::kem::ML_KEM_768_CT_LEN;
use crate::suite::algo;

/// The PQXDH initial message an initiator sends to a responder (ADR-004 §Wire).
///
/// Carries every public value the responder needs to re-derive `SK` and the
/// transcript: the initiator's identity DH key `IK_A`, its ephemeral `EK_A`, the
/// KEM ciphertext, which responder prekeys were targeted (signed-prekey id and
/// the optional one-time-prekey id), and the negotiated suite/context. It is a
/// canonical-CBOR body under [`PQXDH_INIT_DOMAIN`] — a payload, not an ADR-008
/// log struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialMessage {
    /// Negotiated ciphersuite id (ADR-003).
    pub suite_id: u16,
    /// Channel identifier this session belongs to (ADR-006).
    pub channel_id: [u8; 32],
    /// Membership epoch (ADR-006).
    pub epoch: u64,
    /// Initiator identity DH public key `IK_A` (algorithm `0x0101`).
    pub ik_a: [u8; X25519_PUB_LEN],
    /// Initiator ephemeral public key `EK_A` (algorithm `0x0101`).
    pub ek_a: [u8; X25519_PUB_LEN],
    /// The responder signed-prekey id this handshake targeted.
    pub signed_prekey_id: u64,
    /// The responder one-time-prekey id, if one was consumed.
    pub one_time_prekey_id: Option<u64>,
    /// ML-KEM-768 ciphertext encapsulated against the responder KEM prekey.
    pub kem_ct: [u8; ML_KEM_768_CT_LEN],
}

impl InitialMessage {
    /// Canonical-CBOR body, fixed field order:
    /// `[curve_algo, kem_algo, suite_id, epoch, signed_prekey_id,
    ///   has_otp, one_time_prekey_id, channel_id, ik_a, ek_a, kem_ct]`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(11)
            .uint(u64::from(algo::X25519))
            .uint(u64::from(algo::ML_KEM_768))
            .uint(u64::from(self.suite_id))
            .uint(self.epoch)
            .uint(self.signed_prekey_id)
            .uint(u64::from(self.one_time_prekey_id.is_some()))
            .uint(self.one_time_prekey_id.unwrap_or(0))
            .bytes(&self.channel_id)
            .bytes(&self.ik_a)
            .bytes(&self.ek_a)
            .bytes(&self.kem_ct);
        e.finish()
    }

    /// Frame the canonical body for the wire as `PQXDH_INIT_DOMAIN ‖ body`.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let body = self.canonical_body();
        let mut out = Vec::with_capacity(PQXDH_INIT_DOMAIN.len() + body.len());
        out.extend_from_slice(PQXDH_INIT_DOMAIN.as_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Parse a wire-framed initial message, rejecting a wrong domain label,
    /// algorithm-ID mismatch (ADR-003 type confusion), or presence inconsistency.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let prefix = PQXDH_INIT_DOMAIN.as_bytes();
        let body = bytes
            .strip_prefix(prefix)
            .ok_or(Error::MalformedBundle("pqxdh-init domain label"))?;
        Self::from_canonical_body(body)
    }

    /// Decode from a canonical body (without the domain prefix).
    pub fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 11 {
            return Err(Error::MalformedBundle("pqxdh-init arity"));
        }
        expect_algo(d.uint()?, algo::X25519)?;
        expect_algo(d.uint()?, algo::ML_KEM_768)?;
        let suite_id = read_u16(d.uint()?)?;
        let epoch = d.uint()?;
        let signed_prekey_id = d.uint()?;
        let has_otp = d.uint()?;
        let otp_id = d.uint()?;
        let one_time_prekey_id = match has_otp {
            0 => {
                if otp_id != 0 {
                    return Err(Error::MalformedBundle("pqxdh-init otp presence mismatch"));
                }
                None
            }
            1 => Some(otp_id),
            _ => return Err(Error::MalformedBundle("pqxdh-init otp flag")),
        };
        let channel_id = fixed32(d.bytes()?)?;
        let ik_a = fixed_x(d.bytes()?)?;
        let ek_a = fixed_x(d.bytes()?)?;
        let kem_ct = fixed_ct(d.bytes()?)?;
        d.finish()?;
        Ok(Self {
            suite_id,
            channel_id,
            epoch,
            ik_a,
            ek_a,
            signed_prekey_id,
            one_time_prekey_id,
            kem_ct,
        })
    }
}

// --------------------------------------------------------------------------
// Decode helpers
// --------------------------------------------------------------------------

fn expect_algo(got: u64, expected: u16) -> Result<()> {
    let got16 = read_u16(got)?;
    if got16 == expected {
        Ok(())
    } else {
        Err(Error::UnexpectedAlgo {
            got: got16,
            expected,
        })
    }
}

fn read_u16(v: u64) -> Result<u16> {
    u16::try_from(v).map_err(|_| Error::UnknownAlgoId(u16::MAX))
}

fn fixed_x(slice: &[u8]) -> Result<[u8; X25519_PUB_LEN]> {
    slice
        .try_into()
        .map_err(|_| Error::InvalidKeyEncoding { algo: algo::X25519 })
}

fn fixed32(slice: &[u8]) -> Result<[u8; 32]> {
    slice
        .try_into()
        .map_err(|_| Error::MalformedBundle("pqxdh-init channel id length"))
}

fn fixed_ct(slice: &[u8]) -> Result<[u8; ML_KEM_768_CT_LEN]> {
    slice.try_into().map_err(|_| Error::InvalidKeyEncoding {
        algo: algo::ML_KEM_768,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(otp: Option<u64>) -> InitialMessage {
        InitialMessage {
            suite_id: 0x0001,
            channel_id: [5u8; 32],
            epoch: 3,
            ik_a: [1u8; 32],
            ek_a: [2u8; 32],
            signed_prekey_id: 9,
            one_time_prekey_id: otp,
            kem_ct: [7u8; ML_KEM_768_CT_LEN],
        }
    }

    #[test]
    fn wire_round_trips_with_and_without_otp() {
        let with = sample(Some(42));
        assert_eq!(InitialMessage::from_wire(&with.to_wire()).unwrap(), with);
        let without = sample(None);
        let decoded = InitialMessage::from_wire(&without.to_wire()).unwrap();
        assert_eq!(decoded, without);
        assert_eq!(decoded.one_time_prekey_id, None);
    }

    #[test]
    fn rejects_wrong_domain_label() {
        let mut wrong = b"vox/other/v1".to_vec();
        wrong.extend_from_slice(&sample(None).canonical_body());
        assert!(matches!(
            InitialMessage::from_wire(&wrong),
            Err(Error::MalformedBundle(_))
        ));
    }

    #[test]
    fn rejects_type_confusion_in_curve_slot() {
        let mut e = Encoder::new();
        e.array(11)
            .uint(u64::from(algo::ML_KEM_768)) // wrong: curve slot
            .uint(u64::from(algo::ML_KEM_768))
            .uint(0x0001)
            .uint(0)
            .uint(0)
            .uint(0)
            .uint(0)
            .bytes(&[0u8; 32])
            .bytes(&[0u8; 32])
            .bytes(&[0u8; 32])
            .bytes(&[0u8; ML_KEM_768_CT_LEN]);
        assert!(matches!(
            InitialMessage::from_canonical_body(&e.finish()),
            Err(Error::UnexpectedAlgo { .. })
        ));
    }

    #[test]
    fn rejects_otp_presence_inconsistency() {
        // has_otp = 0 but otp_id != 0.
        let mut e = Encoder::new();
        e.array(11)
            .uint(u64::from(algo::X25519))
            .uint(u64::from(algo::ML_KEM_768))
            .uint(0x0001)
            .uint(0)
            .uint(0)
            .uint(0) // has_otp = false
            .uint(5) // but id set
            .bytes(&[0u8; 32])
            .bytes(&[0u8; 32])
            .bytes(&[0u8; 32])
            .bytes(&[0u8; ML_KEM_768_CT_LEN]);
        assert!(matches!(
            InitialMessage::from_canonical_body(&e.finish()),
            Err(Error::MalformedBundle(_))
        ));
    }
}
