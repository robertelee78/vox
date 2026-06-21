//! "ssh over Vox": OpenSSH certificate issuance bound to the verified Vox identity
//! (ADR-013 §"SSH-CA mapping").
//!
//! Vox issues a standard **OpenSSH user certificate**
//! (`ssh-ed25519-cert-v01@openssh.com`) so that connecting with `ssh` over a Vox
//! tunnel needs no host-key TOFU and no separate SSH account: the authority is the
//! member's verified Vox identity (ADR-002). Field mapping (ADR-013, verbatim):
//!
//! - `key_id` = the Vox identity fingerprint (hex of the 32-byte digest);
//! - `valid_principals` = the granted role/service tags **used verbatim** (the
//!   `#`-prefixed string — `#ops` is the principal `#ops`, not `ops`);
//! - an extension carries the governing Vox capability (`dial:<service>`);
//! - `valid_after` / `valid_before` = a short window (**default 5 min**);
//! - signed by the **channel SSH-CA key** (an `admin`-delegated capability in the
//!   ADR-007 tree). The SSH host trusts this CA via an `@cert-authority` line, so
//!   the host's identity is its verified Vox identity — no host-key TOFU.
//!
//! The user public key embedded in the certificate is the **Ed25519 half** of the
//! member's composite identity (ADR-002 layout `ed25519 ‖ ml-dsa`), since OpenSSH
//! speaks Ed25519; the binding to the full composite identity is carried by the
//! `key_id` fingerprint and the Vox transport authentication (ADR-011).
//!
//! This module produces and verifies the exact OpenSSH wire format; interoperation
//! with a real `sshd` is a deployment-level manual check (the format here is the
//! one OpenSSH defines in PROTOCOL.certkeys).

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::{Error, Result};
use crate::hash::{Digest32, ED25519_PUB_LEN};
use crate::identity::rng::random_array;

/// The OpenSSH user-certificate key type string.
pub const SSH_ED25519_CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";
/// The OpenSSH Ed25519 key/signature algorithm name.
pub const SSH_ED25519: &str = "ssh-ed25519";
/// The extension name carrying the governing Vox capability (`dial:<service>`).
pub const VOX_CAPABILITY_EXT: &str = "vox-capability@vox.lux";
/// SSH certificate type for a *user* certificate (vs `2` = host).
const SSH_CERT_TYPE_USER: u32 = 1;
/// Default certificate validity window in seconds (ADR-013: short, default 5 min).
pub const DEFAULT_VALIDITY_SECS: u64 = 5 * 60;

// --- SSH wire helpers (RFC 4251 §5: strings are u32-length-prefixed) ---

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// The Ed25519 public-key blob: `string "ssh-ed25519" ‖ string pubkey`.
fn ed25519_pub_blob(pubkey: &[u8; ED25519_PUB_LEN]) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, SSH_ED25519.as_bytes());
    put_string(&mut b, pubkey);
    b
}

/// Encode a principals list: a string field containing a sequence of strings.
fn principals_blob(principals: &[String]) -> Vec<u8> {
    let mut b = Vec::new();
    for p in principals {
        put_string(&mut b, p.as_bytes());
    }
    b
}

/// Encode the extensions field carrying the single Vox-capability extension: a
/// sequence of `(name, data)` string pairs, where the data for a valued option is
/// itself a string-wrapped value (OpenSSH PROTOCOL.certkeys convention).
fn extensions_blob(dial_capability: &str) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, VOX_CAPABILITY_EXT.as_bytes());
    let mut data = Vec::new();
    put_string(&mut data, dial_capability.as_bytes());
    put_string(&mut b, &data);
    b
}

/// The channel SSH certificate authority — the Ed25519 key that signs user
/// certificates (an `admin`-delegated capability in the ADR-007 tree, ADR-013).
pub struct SshCertAuthority {
    signing_key: SigningKey,
}

impl SshCertAuthority {
    /// Construct the CA from its 32-byte Ed25519 seed (the channel SSH-CA key).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// The CA's Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; ED25519_PUB_LEN] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The `@cert-authority` trust line a host installs so it trusts this CA (and
    /// therefore any Vox identity the CA certifies — no host-key TOFU). `principals`
    /// scopes which principals the CA may certify (`*` for any).
    #[must_use]
    pub fn cert_authority_line(&self, principals: &str) -> String {
        let blob = ed25519_pub_blob(&self.public_key());
        format!(
            "@cert-authority {principals} {SSH_ED25519} {}",
            base64_encode(&blob)
        )
    }

    /// Issue a signed OpenSSH user certificate. Returns the binary certificate blob.
    pub fn issue_user_cert(&self, params: &UserCertParams) -> Result<Vec<u8>> {
        if params.valid_before <= params.valid_after {
            return Err(Error::MalformedTunnel("ssh cert validity window empty"));
        }
        // Reject an empty principals list: in OpenSSH a certificate with *no*
        // principals is valid for ANY principal of its type — a silent
        // authorization expansion. ADR-013 requires the granted tags verbatim, so a
        // certificate must name at least one principal.
        if params.principals.is_empty() {
            return Err(Error::MalformedTunnel("ssh cert requires >= 1 principal"));
        }
        let nonce: [u8; 32] = random_array()?;

        let mut blob = Vec::new();
        put_string(&mut blob, SSH_ED25519_CERT_TYPE.as_bytes());
        put_string(&mut blob, &nonce);
        put_string(&mut blob, params.user_ed25519); // the 'pk' field
        put_u64(&mut blob, params.serial);
        put_u32(&mut blob, SSH_CERT_TYPE_USER);
        put_string(&mut blob, hex(params.vox_fingerprint).as_bytes()); // key_id
        put_string(&mut blob, &principals_blob(params.principals));
        put_u64(&mut blob, params.valid_after);
        put_u64(&mut blob, params.valid_before);
        put_string(&mut blob, &[]); // critical options: none
        put_string(&mut blob, &extensions_blob(params.dial_capability));
        put_string(&mut blob, &[]); // reserved
        put_string(&mut blob, &ed25519_pub_blob(&self.public_key())); // signature key

        // Sign everything so far, then append the signature blob.
        let sig = self.signing_key.sign(&blob);
        let mut sig_blob = Vec::new();
        put_string(&mut sig_blob, SSH_ED25519.as_bytes());
        put_string(&mut sig_blob, &sig.to_bytes());
        put_string(&mut blob, &sig_blob);
        Ok(blob)
    }

    /// The full authorized-keys-style certificate line for a user (what the client
    /// presents to `ssh` via its cert file).
    pub fn issue_user_cert_line(&self, params: &UserCertParams) -> Result<String> {
        let blob = self.issue_user_cert(params)?;
        Ok(format!("{SSH_ED25519_CERT_TYPE} {}", base64_encode(&blob)))
    }
}

/// The inputs to [`SshCertAuthority::issue_user_cert`] (ADR-013 field mapping).
#[derive(Clone, Copy, Debug)]
pub struct UserCertParams<'a> {
    /// The Ed25519 half of the member's composite identity (the certified key).
    pub user_ed25519: &'a [u8; ED25519_PUB_LEN],
    /// The Vox identity fingerprint → the cert `key_id` (hex).
    pub vox_fingerprint: &'a Digest32,
    /// The granted role/service tags, used verbatim as `valid_principals`.
    pub principals: &'a [String],
    /// The governing Vox capability (e.g. `"dial:ssh-hosts"`) carried as an extension.
    pub dial_capability: &'a str,
    /// A caller-chosen monotonic certificate serial.
    pub serial: u64,
    /// Validity window start (epoch-seconds).
    pub valid_after: u64,
    /// Validity window end (epoch-seconds) — keep short (ADR-013, default 5 min).
    pub valid_before: u64,
}

/// The certificate fields a verifier recovers (the subset Vox checks).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCert {
    /// The certified user Ed25519 public key.
    pub user_ed25519: [u8; ED25519_PUB_LEN],
    /// The `key_id` (the Vox identity fingerprint, hex).
    pub key_id: String,
    /// The certified principals (verbatim role/service tags).
    pub principals: Vec<String>,
    /// Validity window start (epoch-seconds).
    pub valid_after: u64,
    /// Validity window end (epoch-seconds).
    pub valid_before: u64,
}

impl VerifiedCert {
    /// Whether the certificate is within its validity window at `now`.
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.valid_after && now < self.valid_before
    }
}

/// Parse and verify an OpenSSH user certificate blob against the expected CA public
/// key, at time `now` (epoch-seconds).
///
/// Checks the type string, that the embedded signature key matches `ca_pubkey`,
/// that the CA signature over the certificate body verifies, **and that `now` is
/// within the certificate's validity window** — an expired or not-yet-valid
/// certificate is rejected ([`Error::TunnelDenied`]), never returned as valid. The
/// caller still confirms the expected principal/`key_id` are present in the returned
/// fields. (Pass `now = 0` only in a context where time is genuinely irrelevant; the
/// window still must contain 0, so prefer a real clock.)
pub fn verify_user_cert(
    blob: &[u8],
    ca_pubkey: &[u8; ED25519_PUB_LEN],
    now: u64,
) -> Result<VerifiedCert> {
    let mut r = Reader::new(blob);
    let cert_type = r.string()?;
    if cert_type != SSH_ED25519_CERT_TYPE.as_bytes() {
        return Err(Error::MalformedTunnel("ssh cert: wrong type"));
    }
    let _nonce = r.string()?;
    let user_ed25519: [u8; ED25519_PUB_LEN] = r
        .string()?
        .try_into()
        .map_err(|_| Error::MalformedTunnel("ssh cert: user key length"))?;
    let _serial = r.u64()?;
    let cert_type_num = r.u32()?;
    if cert_type_num != SSH_CERT_TYPE_USER {
        return Err(Error::MalformedTunnel("ssh cert: not a user cert"));
    }
    let key_id = String::from_utf8(r.string()?.to_vec())
        .map_err(|_| Error::MalformedTunnel("ssh cert: key_id utf8"))?;
    let principals = parse_string_seq(r.string()?)?;
    let valid_after = r.u64()?;
    let valid_before = r.u64()?;
    let _critical = r.string()?;
    let _extensions = r.string()?;
    let _reserved = r.string()?;
    let sig_key = r.string()?;
    if sig_key != ed25519_pub_blob(ca_pubkey).as_slice() {
        return Err(Error::MalformedTunnel("ssh cert: signature key != CA"));
    }
    // The signed region is everything up to (not including) the signature string.
    let signed_len = r.pos();
    let sig_blob = r.string()?;
    r.finish()?;

    // sig_blob = string("ssh-ed25519") ‖ string(sig64)
    let mut sr = Reader::new(sig_blob);
    if sr.string()? != SSH_ED25519.as_bytes() {
        return Err(Error::MalformedTunnel("ssh cert: sig algo"));
    }
    let sig_bytes: [u8; 64] = sr
        .string()?
        .try_into()
        .map_err(|_| Error::MalformedTunnel("ssh cert: sig length"))?;
    sr.finish()?;

    let vk = VerifyingKey::from_bytes(ca_pubkey)
        .map_err(|_| Error::MalformedTunnel("ssh cert: bad CA key"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify(&blob[..signed_len], &sig)
        .map_err(|_| Error::SignatureInvalid)?;

    let cert = VerifiedCert {
        user_ed25519,
        key_id,
        principals,
        valid_after,
        valid_before,
    };
    // A correctly-signed but expired/not-yet-valid certificate does not authorize:
    // reject it here so verification means "valid now", not merely "well-signed".
    if !cert.is_valid_at(now) {
        return Err(Error::TunnelDenied("ssh cert outside validity window"));
    }
    Ok(cert)
}

/// Parse a sequence-of-strings field into its component strings.
fn parse_string_seq(bytes: &[u8]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut r = Reader::new(bytes);
    while !r.is_empty() {
        let s = r.string()?;
        out.push(
            String::from_utf8(s.to_vec())
                .map_err(|_| Error::MalformedTunnel("ssh cert: principal utf8"))?,
        );
    }
    Ok(out)
}

/// A minimal SSH wire reader.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn pos(&self) -> usize {
        self.pos
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::MalformedTunnel("ssh cert: length overflow"))?;
        if end > self.buf.len() {
            return Err(Error::MalformedTunnel("ssh cert: truncated"));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
    fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn finish(self) -> Result<()> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::MalformedTunnel("ssh cert: trailing bytes"))
        }
    }
}

/// Lowercase hex of a digest (the `key_id` encoding).
fn hex(d: &Digest32) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
    }
    s
}

/// Standard base64 (RFC 4648) encoding, for the authorized-keys text lines.
fn base64_encode(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            A[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca() -> SshCertAuthority {
        SshCertAuthority::from_seed(&[42u8; 32])
    }

    fn params<'a>(
        user: &'a [u8; ED25519_PUB_LEN],
        fpr: &'a Digest32,
        principals: &'a [String],
        after: u64,
        before: u64,
    ) -> UserCertParams<'a> {
        UserCertParams {
            user_ed25519: user,
            vox_fingerprint: fpr,
            principals,
            dial_capability: "dial:ssh-hosts",
            serial: 1,
            valid_after: after,
            valid_before: before,
        }
    }

    #[test]
    fn issue_then_verify_round_trips() {
        let ca = ca();
        let user = [9u8; ED25519_PUB_LEN];
        let fpr = [0xAB; 32];
        let principals = vec!["#ops".to_owned(), "#ssh-hosts".to_owned()];
        let blob = ca
            .issue_user_cert(&params(&user, &fpr, &principals, 1000, 1300))
            .unwrap();
        let v = verify_user_cert(&blob, &ca.public_key(), 1200).unwrap();
        assert_eq!(v.user_ed25519, user);
        assert_eq!(v.principals, principals, "principals are verbatim, # kept");
        assert_eq!(v.key_id, hex(&fpr));
        assert_eq!((v.valid_after, v.valid_before), (1000, 1300));
        assert!(v.is_valid_at(1200) && !v.is_valid_at(1300) && !v.is_valid_at(999));
    }

    #[test]
    fn expired_or_not_yet_valid_cert_is_rejected_by_verification() {
        let ca = ca();
        let user = [9u8; ED25519_PUB_LEN];
        let fpr = [0xAB; 32];
        let p = vec!["#ops".to_owned()];
        let blob = ca
            .issue_user_cert(&params(&user, &fpr, &p, 1000, 1300))
            .unwrap();
        // After the window: rejected.
        assert!(matches!(
            verify_user_cert(&blob, &ca.public_key(), 1300),
            Err(Error::TunnelDenied(_))
        ));
        // Before the window: rejected.
        assert!(matches!(
            verify_user_cert(&blob, &ca.public_key(), 999),
            Err(Error::TunnelDenied(_))
        ));
        // Inside: accepted.
        assert!(verify_user_cert(&blob, &ca.public_key(), 1000).is_ok());
    }

    #[test]
    fn empty_principals_is_rejected_at_issuance() {
        let ca = ca();
        let none: Vec<String> = vec![];
        assert!(matches!(
            ca.issue_user_cert(&params(&[1u8; 32], &[2u8; 32], &none, 0, 60)),
            Err(Error::MalformedTunnel(_))
        ));
    }

    #[test]
    fn wrong_ca_key_fails_verification() {
        let ca = ca();
        let other = SshCertAuthority::from_seed(&[7u8; 32]);
        let p = vec!["#ops".to_owned()];
        let blob = ca
            .issue_user_cert(&params(&[1u8; 32], &[2u8; 32], &p, 0, 60))
            .unwrap();
        // Verifying against a different CA key is rejected (sig-key mismatch).
        assert!(verify_user_cert(&blob, &other.public_key(), 30).is_err());
    }

    #[test]
    fn tampered_cert_fails_verification() {
        let ca = ca();
        let p = vec!["#ops".to_owned()];
        let mut blob = ca
            .issue_user_cert(&params(&[1u8; 32], &[2u8; 32], &p, 0, 60))
            .unwrap();
        // Flip a byte in the key_id region (well inside the signed body).
        let n = blob.len();
        blob[n / 2] ^= 0xff;
        assert!(verify_user_cert(&blob, &ca.public_key(), 30).is_err());
    }

    #[test]
    fn empty_validity_window_is_rejected() {
        let ca = ca();
        let p = vec!["#ops".to_owned()];
        assert!(ca
            .issue_user_cert(&params(&[1u8; 32], &[2u8; 32], &p, 100, 100))
            .is_err());
    }

    #[test]
    fn authority_and_cert_lines_are_well_formed() {
        let ca = ca();
        let line = ca.cert_authority_line("*");
        assert!(line.starts_with("@cert-authority * ssh-ed25519 "));
        let p = vec!["#ops".to_owned()];
        let cert = ca
            .issue_user_cert_line(&params(&[1u8; 32], &[2u8; 32], &p, 0, 60))
            .unwrap();
        assert!(cert.starts_with("ssh-ed25519-cert-v01@openssh.com "));
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
