[0m
> build · glm-5.3
[0m
[0m→ [0mRead docs/adr/ADR-017-room-bound-services.md
I'll work through this systematically: ADRs first, then the code, then the Tor reference.
[0m→ [0mRead docs/adr/ADR-013-overlay-tunneling.md
[0m→ [0mRead docs/adr/ADR-007-membership-consent-and-admin-governance.md
[0m✗ [0mRead crates/vox-core/src/governance/channel.rs failed
[91m[1mError: [0mFile not found: crates/vox-core/src/governance/channel.rs
[0m→ [0mRead crates/vox-core/src/governance/servicegrant.rs
Now the governance code:
[0m✱ [0mGlob "crates/vox-core/src/**/*.rs"[90m 100 matches[0m
[0m→ [0mRead crates/vox-core/src/governance/genesis.rs
`channel.rs` lives in `node/`, not `governance/`. Reading the governance files:
[0m→ [0mRead crates/vox-core/src/governance/evaluator.rs
Now the node files. `channel.rs` is likely large — reading it and `resolver.rs` first:
[0m
[0m$ [0mwc -l crates/vox-core/src/node/channel.rs crates/vox-core/src/node/resolver.rs crates/vox-core/src/node/up.rs crates/vox-core/src/node/actor.rs crates/vox-core/src/node/link.rs crates/vox-core/src/tunnel/*.rs crates/vox-tui/src/cli.rs
2323 crates/vox-core/src/node/channel.rs
     136 crates/vox-core/src/node/resolver.rs
     175 crates/vox-core/src/node/up.rs
    3107 crates/vox-core/src/node/actor.rs
     361 crates/vox-core/src/node/link.rs
      59 crates/vox-core/src/tunnel/addr.rs
      90 crates/vox-core/src/tunnel/authz.rs
     208 crates/vox-core/src/tunnel/service.rs
     292 crates/vox-core/src/tunnel/session.rs
     210 crates/vox-core/src/tunnel/socks.rs
     386 crates/vox-core/src/tunnel/sshca.rs
     592 crates/vox-tui/src/cli.rs
    7939 total
[0m
[0m→ [0mRead crates/vox-core/src/node/channel.rs
[0m→ [0mRead crates/vox-core/src/node/channel.rs[90m [limit=1030, offset=1295][0m
[0m→ [0mRead crates/vox-core/src/node/resolver.rs
[0m→ [0mRead crates/vox-core/src/node/up.rs
[0m→ [0mRead crates/vox-core/src/node/link.rs
[0m→ [0mRead crates/vox-core/src/tunnel/session.rs
[0m→ [0mRead crates/vox-core/src/tunnel/authz.rs
Now the tunnel modules:
[0m→ [0mRead crates/vox-core/src/tunnel/service.rs
[0m✱ [0mGrep "learn_members|admit_author|vouch|Serve|Up|resolver|Resolver|tunnel|service_grant|authors\.keys"[90m in crates/vox-core/src/node/actor.rs · 100 matches[0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [limit=160, offset=2060][0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [limit=200, offset=2700][0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [limit=130, offset=700][0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [limit=120, offset=940][0m
[0m✱ [0mGrep "async fn serve_room|async fn consent|async fn revoke|async fn join_channel|async fn add_service"[90m in crates/vox-core/src/node/actor.rs · 5 matches[0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [limit=140, offset=2560][0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [limit=120, offset=1840][0m
[0m→ [0mRead crates/vox-tui/src/cli.rs
Now the CLI and the gate tests:
[0m✱ [0mGlob "**/tests/**/*.rs"[90m 15 matches[0m
[0m→ [0mRead crates/vox-core/tests/node_m17_up_gate.rs
[0m
[0m$ [0msed -n '880,960p' /opt/tor/src/feature/hs/hs_common.c
}

  /* Validate that this pubkey does not have a torsion component. We need to do
   * this on the prop224 client-side so that attackers can't give equivalent
   * forms of an onion address to users. */
  if (ed25519_validate_pubkey(&service_pubkey) < 0) {
    log_warn(LD_REND, "Service address %s has bad pubkey .",
             escaped_safe_str(address));
    goto invalid;
  }

  /* Valid address. */
  return 1;
 invalid:
  return 0;
}

/** Build a service address using an ed25519 public key and a given version.
 * The returned address is base32 encoded and put in addr_out. The caller MUST
 * make sure the addr_out is at least HS_SERVICE_ADDR_LEN_BASE32 + 1 long.
 *
 * Format is as follows:
 *     base32(PUBKEY || CHECKSUM || VERSION)
 *     CHECKSUM = H(".onion checksum" || PUBKEY || VERSION)
 * */
void
hs_build_address(const ed25519_public_key_t *key, uint8_t version,
                 char *addr_out)
{
  uint8_t checksum[DIGEST256_LEN];
  char address[HS_SERVICE_ADDR_LEN];

  tor_assert(key);
  tor_assert(addr_out);

  /* Get the checksum of the address. */
  build_hs_checksum(key, version, checksum);
  /* Get the binary address representation. */
  build_hs_address(key, checksum, version, address);

  /* Encode the address. addr_out will be NUL terminated after this. */
  base32_encode(addr_out, HS_SERVICE_ADDR_LEN_BASE32 + 1, address,
                sizeof(address));
  /* Validate what we just built. */
  tor_assert(hs_address_is_valid(addr_out));
}

/** From a given ed25519 public key pk and an optional secret, compute a
 * blinded public key and put it in blinded_pk_out. This is only useful to
 * the client side because the client only has access to the identity public
 * key of the service. */
void
hs_build_blinded_pubkey(const ed25519_public_key_t *pk,
                        const uint8_t *secret, size_t secret_len,
                        uint64_t time_period_num,
                        ed25519_public_key_t *blinded_pk_out)
{
  /* Our blinding key API requires a 32 bytes parameter. */
  uint8_t param[DIGEST256_LEN];

  tor_assert(pk);
  tor_assert(blinded_pk_out);
  tor_assert(!fast_mem_is_zero((char *) pk, ED25519_PUBKEY_LEN));

  build_blinded_key_param(pk, secret, secret_len,
                          time_period_num, get_time_period_length(), param);
  ed25519_public_blind(blinded_pk_out, pk, param);

  memwipe(param, 0, sizeof(param));
}

/** From a given ed25519 keypair kp and an optional secret, compute a blinded
 * keypair for the current time period and put it in blinded_kp_out. This is
 * only useful by the service side because the client doesn't have access to
 * the identity secret key. */
void
hs_build_blinded_keypair(const ed25519_keypair_t *kp,
                         const uint8_t *secret, size_t secret_len,
                         uint64_t time_period_num,
                         ed25519_keypair_t *blinded_kp_out)
{
[0m
The M17.3 gate claim checks out (asserts membership-granted dial at `node_m17_up_gate.rs:118-143`). Now the Tor reference:
[0m$ [0msed -n '1,60p' /opt/tor/src/feature/hs/hs_descriptor.c; echo ---; sed -n '700,730p' /opt/tor/src/feature/hs/hs_descriptor.c; echo ---; sed -n '1400,1440p' /opt/tor/src/feature/hs/hs_descriptor.c
/* Copyright (c) 2016-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_descriptor.c
 * \brief Handle hidden service descriptor encoding/decoding.
 *
 * \details
 * Here is a graphical depiction of an HS descriptor and its layers:
 *
 *      +------------------------------------------------------+
 *      |DESCRIPTOR HEADER:                                    |
 *      |  hs-descriptor 3                                     |
 *      |  descriptor-lifetime 180                             |
 *      |  ...                                                 |
 *      |  superencrypted                                      |
 *      |+---------------------------------------------------+ |
 *      ||SUPERENCRYPTED LAYER (aka OUTER ENCRYPTED LAYER):  | |
 *      ||  desc-auth-type x25519                            | |
 *      ||  desc-auth-ephemeral-key                          | |
 *      ||  auth-client                                      | |
 *      ||  auth-client                                      | |
 *      ||  ...                                              | |
 *      ||  encrypted                                        | |
 *      ||+-------------------------------------------------+| |
 *      |||ENCRYPTED LAYER (aka INNER ENCRYPTED LAYER):     || |
 *      |||  create2-formats                                || |
 *      |||  intro-auth-required                            || |
 *      |||  introduction-point                             || |
 *      |||  introduction-point                             || |
 *      |||  ...                                            || |
 *      ||+-------------------------------------------------+| |
 *      |+---------------------------------------------------+ |
 *      +------------------------------------------------------+
 *
 * The DESCRIPTOR HEADER section is completely unencrypted and contains generic
 * descriptor metadata.
 *
 * The SUPERENCRYPTED LAYER section is the first layer of encryption, and it's
 * encrypted using the blinded public key of the hidden service to protect
 * against entities who don't know its onion address. The clients of the hidden
 * service know its onion address and blinded public key, whereas third-parties
 * (like HSDirs) don't know it (except if it's a public hidden service).
 *
 * The ENCRYPTED LAYER section is the second layer of encryption, and it's
 * encrypted using the client authorization key material (if those exist). When
 * client authorization is enabled, this second layer of encryption protects
 * the descriptor content from unauthorized entities. If client authorization
 * is disabled, this second layer of encryption does not provide any extra
 * security but is still present. The plaintext of this layer contains all the
 * information required to connect to the hidden service like its list of
 * introduction points.
 **/

/* For unit tests.*/
#define HS_DESCRIPTOR_PRIVATE

#include <stdbool.h>
#include "core/or/or.h"
#include "app/config/config.h"
---
  tor_assert(!fast_mem_is_zero((char *) client->field,              \
                              sizeof(client->field)));             \
  ret = base64_encode_nopad(field##_b64, sizeof(field##_b64),      \
                            client->field, sizeof(client->field)); \
  tor_assert(ret > 0);                                             \
  STMT_END

  ASSERT_AND_BASE64(client_id);
  ASSERT_AND_BASE64(iv);
  ASSERT_AND_BASE64(encrypted_cookie);

  /* Build the final string */
  tor_asprintf(&auth_client_str, "%s %s %s %s", str_desc_auth_client,
               client_id_b64, iv_b64, encrypted_cookie_b64);

#undef ASSERT_AND_BASE64

  return auth_client_str;
}

/** Create the "client-auth" part of the descriptor and return a
 *  newly-allocated string with it. It's the responsibility of the caller to
 *  free the returned string. */
static char *
get_all_auth_client_lines(const hs_descriptor_t *desc)
{
  smartlist_t *auth_client_lines = smartlist_new();
  char *auth_client_lines_str = NULL;

  tor_assert(desc);
  tor_assert(desc->superencrypted_data.clients);
---
  return -1;
}

/** Return true iff the given length of the encrypted data of a descriptor
 * passes validation. */
STATIC int
encrypted_data_length_is_valid(size_t len)
{
  /* Make sure there is enough data for the salt and the mac. The equality is
     there to ensure that there is at least one byte of encrypted data. */
  if (len <= HS_DESC_ENCRYPTED_SALT_LEN + DIGEST256_LEN) {
    log_warn(LD_REND, "Length of descriptor's encrypted data is too small. "
                      "Got %lu but minimum value is %d",
             (unsigned long)len, HS_DESC_ENCRYPTED_SALT_LEN + DIGEST256_LEN);
    goto err;
  }

  return 1;
 err:
  return 0;
}

/** Build the KEYS component for the authorized client computation. The format
 * of the construction is:
 *
 *    SECRET_SEED = x25519(sk, pk)
 *    KEYS = KDF(subcredential | SECRET_SEED, 40)
 *
 * Set the <b>keys_out</b> argument to point to the buffer containing the KEYS,
 * and return the buffer's length. The caller should wipe and free its content
 * once done with it. This function can't fail. */
static size_t
build_descriptor_cookie_keys(const hs_subcredential_t *subcredential,
                             const curve25519_secret_key_t *sk,
                             const curve25519_public_key_t *pk,
                             uint8_t **keys_out)
{
  uint8_t secret_seed[CURVE25519_OUTPUT_LEN];
  uint8_t *keystream;
  size_t keystream_len = HS_DESC_CLIENT_ID_LEN + HS_DESC_COOKIE_KEY_LEN;
  crypto_xof_t *xof;
[0m
[0m→ [0mRead crates/vox-core/src/node/tunnel.rs
Now the remaining node pieces — tunnel serving, membership view, and the anchor gate:
[0m→ [0mRead crates/vox-core/src/governance/membership.rs
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [limit=80, offset=1290][0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [limit=120, offset=1390][0m
[0m→ [0mRead crates/vox-core/src/node/circuitstream.rs[90m [limit=120, offset=255][0m
[0m✱ [0mGrep "release_key_to|issue_consent|auto|consent_all|consent_to_all"[90m in crates/vox-core/src/node/actor.rs · 13 matches[0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [limit=140, offset=1700][0m
Line 1764 looks like an automatic consent path — critical for Q1. Reading it:
[0m✱ [0mGrep "fn rotated|chain_id|CHAIN"[90m in crates/vox-core/src/group · 100 matches[0m
Found a significant issue at actor.rs:1758-1764 (auto-consent to the join responder). Now verifying the remaining claims — chain_id semantics, ADR-006 sealing, anchors-as-config, and the M15 gate:
[0m
[0m$ [0mrg -n "anchors" crates/vox-core/src/node/paths.rs crates/vox-core/src/node/headless.rs crates/vox-tui/src/app.rs 2>/dev/null | head -30; echo ---; rg -rn "config_dir" crates/vox-core/src/node/paths.rs | head
crates/vox-tui/src/app.rs:263:    anchors: vox_core::nat::bootstrap::BootstrapSet,
crates/vox-tui/src/app.rs:274:        .anchors(anchors)
crates/vox-tui/src/app.rs:314:    anchors: vox_core::nat::bootstrap::BootstrapSet,
crates/vox-tui/src/app.rs:322:        .anchors(anchors);
---
    pub n: PathBuf,
        let n = match config_override {
        create_private_dir(&n)?;
            n,
[0m
[0m$ [0mrg -rn "anchors" crates/vox-core/src/node/headless.rs | head -20; echo ---; rg -n "write|config" crates/vox-core/src/node/headless.rs | head -20; echo ---; rg -rn "\"anchors\"|/anchors|anchors_file|anchor_file|anchors_path" crates/ --glob '*.rs' | head -20
---
21:use crate::node::paths::{write_private_file, Paths};
45:            write_private_file(&path, &fresh)?;
---
crates/vox-core/src/node/actor.rs:            .field(n, &self.anchors.len())
[0m
[0m→ [0mRead crates/vox-core/src/node/headless.rs
[0m
[0m$ [0mrg -rn "anchors" crates/vox-tui/src/ --glob '*.rs' | grep -vi "anchor_set\|anchors:" | head -30; echo ===; rg -rn "config_dir" crates/vox-tui/src/tunnel_cli.rs crates/vox-tui/src/app.rs 2>/dev/null | head; echo ===; rg -rn "anchor" crates/vox-core/src/node/paths.rs | head
crates/vox-tui/src/cli.rs:    pub n: Vec<String>,
crates/vox-tui/src/cli.rs:    /// The configured n, parsed and merged by identity.
crates/vox-tui/src/cli.rs:        for spec in &self.n {
crates/vox-tui/src/cli.rs:        n,
crates/vox-tui/src/cli.rs:    let n_for_body = n.clone();
crates/vox-tui/src/cli.rs:        let node = crate::tunnel_cli::open_profile(paths, listen, n, &identity).await?;
crates/vox-tui/src/cli.rs:        body(node, n_for_body).await
crates/vox-tui/src/cli.rs:        n: std::env::var("VOX_ANCHORS")
crates/vox-tui/src/cli.rs:            match run_live(paths, args.listen, n) {
crates/vox-tui/src/cli.rs:            match run_node(paths, args.listen, n) {
crates/vox-tui/src/cli.rs:                move |node, n| async move {
crates/vox-tui/src/cli.rs:                    crate::tunnel_cli::serve(&node, &n, &a.name, a.port, a.at).await
crates/vox-tui/src/cli.rs:                move |node, _n| async move {
crates/vox-tui/src/app.rs:    n: vox_core::nat::bootstrap::BootstrapSet,
crates/vox-tui/src/app.rs:        .n(n)
crates/vox-tui/src/app.rs:    n: vox_core::nat::bootstrap::BootstrapSet,
crates/vox-tui/src/app.rs:        .n(n);
crates/vox-tui/src/tunnel_cli.rs:    n: vox_core::nat::bootstrap::BootstrapSet,
crates/vox-tui/src/tunnel_cli.rs:    let cfg = NodeConfig::new().bind(Bind::Addr(listen)).n(n);
crates/vox-tui/src/tunnel_cli.rs:    n: vox_core::nat::bootstrap::BootstrapSet,
crates/vox-tui/src/tunnel_cli.rs:    let cfg = NodeConfig::new().bind(Bind::Addr(listen)).n(n);
crates/vox-tui/src/tunnel_cli.rs:fn reachable_or_relayed(node: &NodeHandle, n: &BootstrapSet) -> bool {
crates/vox-tui/src/tunnel_cli.rs:    if !n.nodes().is_empty() {
crates/vox-tui/src/tunnel_cli.rs:    n: &BootstrapSet,
crates/vox-tui/src/tunnel_cli.rs:    if !reachable_or_relayed(node, n) {
crates/vox-tui/src/tunnel_cli.rs:    /// The n to reach the swarm through.
crates/vox-tui/src/tunnel_cli.rs:    pub n: vox_core::nat::bootstrap::BootstrapSet,
crates/vox-tui/src/tunnel_cli.rs:        target.n,
zsh:1: == not found
[0m
[0m$ [0mrg -rln "anchors" crates/vox-core/src/node/ | head; echo ---; rg -n "join.*anchors|anchors.*file|write.*anchor|anchor.*write" crates/vox-core/src/node/actor.rs | head; echo ---; ls crates/vox-core/src/node/paths.rs && rg -n "pub fn|const" crates/vox-core/src/node/paths.rs | head -20
crates/vox-core/src/node/api.rs:    /// ln, whether or not it is a member — in channelID order. What an anchor
crates/vox-core/src/node/network.rs:    /// eligible to open a `join` stream. And a node that *ln* a channel it is
crates/vox-core/src/node/network.rs:    /// node holds or ln.
crates/vox-core/src/node/network.rs:    /// Whether the board knows `peer` as a member of some channel it ln: the
crates/vox-core/src/node/network.rs:    /// What this node's board ln: every channel it holds a genesis for, with
crates/vox-core/src/node/coordstream.rs:        // Relaying is work done for members and ln only.
crates/vox-core/src/node/actor.rs:    /// The ln this node publishes to, reads from, climbs its ladder through and
crates/vox-core/src/node/actor.rs:    pub ln: BootstrapSet,
crates/vox-core/src/node/actor.rs:            .field("ln", &self.ln.len())
crates/vox-core/src/node/actor.rs:    /// ln.
---
1123:                let _ = channel.add_anchors(profile.store(), &add);
---
crates/vox-core/src/node/paths.rs
18:pub const VAULT_FILE: &str = "vault.cbor";
20:pub const STORE_FILE: &str = "store.redb";
22:pub const DEFAULT_PROFILE: &str = "default";
36:    pub fn resolve(
74:    pub fn vault_file(&self) -> PathBuf {
80:    pub fn store_file(&self) -> PathBuf {
120:pub fn create_private_dir(dir: &Path) -> Result<()> {
129:pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
[0m
[0m$ [0mrg -rln --glob '*.rs' "anchors\b" crates/ | xargs rg -ln "config" 2>/dev/null | head; echo ---; rg -n "SEG_ANCHORS|add_anchors|adopt_channel_anchors" crates/vox-core/src/node/actor.rs | head -12; echo ---; rg -rn "anchor" crates/vox-tui/src/tunnel_cli.rs | head -25
---
1112:    async fn adopt_channel_anchors(&mut self, channel_id: &Digest32, more: Option<&BootstrapSet>) {
1123:                let _ = channel.add_anchors(profile.store(), &add);
1747:        self.adopt_channel_anchors(&parsed.channel_id, Some(&learned))
2550:                self.adopt_channel_anchors(&id, None).await;
2604:        self.adopt_channel_anchors(&id, None).await;
2627:                self.adopt_channel_anchors(channel_id, None).await;
---
    ns: vox_core::nat::bootstrap::BootstrapSet,
    let cfg = NodeConfig::new().bind(Bind::Addr(listen)).ns(ns);
    ns: vox_core::nat::bootstrap::BootstrapSet,
    let cfg = NodeConfig::new().bind(Bind::Addr(listen)).ns(ns);
/// routable advertised endpoint, or an n that will relay for it.
fn reachable_or_relayed(node: &NodeHandle, ns: &BootstrapSet) -> bool {
    if !ns.nodes().is_empty() {
    ns: &BootstrapSet,
    if !reachable_or_relayed(node, ns) {
            "this machine has no address a guest could reach and no n to relay \
             `<fingerprint>@<multiaddr>` here as --n,\n       or open a port on \
    /// The ns to reach the swarm through.
    pub ns: vox_core::nat::bootstrap::BootstrapSet,
        target.ns,
[0m
[0m$ [0mrg -n "grant|consent|approve|dial" crates/vox-core/tests/node_m15_anchor_gate.rs | head -40
5://! network of `support/vnet.rs`, where a direct dial is dropped and a hole punch is
199:        // moment it is up, not after a direct dial and a punch have each timed out.
227:        // ---- Alice sees Bob join, consents, and they talk ----
248:        assert!(out.is_done(), "Alice consents to Bob: {out:?}");
360:        // ---- both online once: create, join, consent ----
448:        assert!(wanted >= 3, "genesis, consent and the message: {wanted}");
511:/// tunnel is nothing more than TCP over a tunnel — grants Bob the capability to dial
628:        // Before any grant the service is dark, even to a member: Bob's forward binds
647:            let _ = app.write_all(b"before the grant").await;
652:                "a service with no capability granted is dark: {read:?}"
660:        // Alice grants Bob dial:ssh — a fact on the room's log.
670:        assert!(out.is_done(), "Alice grants Bob dial:ssh: {out:?}");
689:                // Try the round trip; until the grant has synced this closes.
709:        .expect("the grant synced and the tunnel carried real bytes");
[0m
[0m$ [0mls docs/adr/ | head -30; echo ---; rg -n "per-recipient|seal|SKDM" docs/adr/ADR-006*.md | head -30
ADR-001-vox-foundation-vision-threat-model-and-principles.md
ADR-002-identity-and-key-model.md
ADR-003-post-quantum-and-crypto-agility-policy.md
ADR-004-pairwise-secure-channel.md
ADR-005-channel-addressing-and-authenticated-join.md
ADR-006-group-messaging-sender-keys.md
ADR-007-membership-consent-and-admin-governance.md
ADR-008-replicated-authenticated-log-and-sync.md
ADR-009-deniability-mode.md
ADR-009-reviews
ADR-009-security-analysis.md
ADR-010-at-rest-storage-and-retention.md
ADR-011-transport-substrate.md
ADR-012-nat-traversal-and-reachability.md
ADR-013-overlay-tunneling.md
ADR-014-macos-client.md
ADR-015-rust-tui-client.md
ADR-016-node-runtime.md
ADR-017-room-bound-services.md
ADR-018-quality-bar-and-product-proof.md
ADR-019-pure-rust-tls-provider.md
README.md
---
7:keep consent are re-keyed at iteration 0, and both are persisted. Known gap (2) is closed. 2026-09-20 — SKDMs are delivered over a `pairwise` stream and receiver chains persist their live state (`node::pairwise_stream`, `node::channel`, ADR-016 M14.5b). 2026-09-19 — status reconciled; Implementation notes (M4) added.
19:per-recipient, which is exactly what per-sender consent needs.
25:Message (SKDM) to each recipient over the pairwise channel (ADR-004). Messages are broadcast once
28:**Per-recipient distribution is the consent hook.** Because each member distributes their own SKDM
29:individually, "consent" is simply *withholding* a member's SKDM from a newcomer until that member
34:confusion; eprint 2023/1385). Every SKDM and message MUST bind `(channelID, epoch)` into its
38:**Post-quantum distribution.** An SKDM is delivered **as an ordinary Double-Ratchet message inside the
40:secret already mixed in by PQXDH — there is **no separate per-SKDM KEM step** (implementers must not
44:**Consent binds to an identity, not a device.** An SKDM is addressed to a recipient *identity*. Under
45:the shared-root multi-device model (ADR-002), the recipient's devices share received SKDMs over the
50:**History delivery (forward-only vs full-history — ADR-007 channel policy).** The SKDM names a starting
52:newly-consented member can read is set by *which* SKDM the sender releases:
53:- **Forward-only channels:** consent releases the SKDM at the sender's **current** `iteration` → the
55:- **Full-history channels (the default, ADR-014):** consent releases the sender's **origin SKDM
67:- **SKDM fields:** `{ channelID, epoch, author_id, chain_id, iteration, chain_key, signing_pubkey,
95:- Larger PQ keys increase SKDM size and distribution cost (O(recipients) per rotation).
105:- **SKDM (tag `0x0002`, `vox/skdm/v1`)** is the canonical body `[cid, epoch, author_id, chain_id,
107:  ADR-004 pairwise session** (`Skdm::seal_into` / `open_from`) — no per-SKDM KEM, exactly the
131:  Origins and the delivery ledger are sealed `KeyMaterial` segments (ADR-010), because a rotation that
138:- **Sender keys are delivered and retained (ADR-016 M14.5b).** An SKDM now travels as one frame on a
139:  bi-stream typed `pairwise`, sealed into the recipient's ADR-004 session (`Skdm::seal_into`), so the
143:  (1) **A receiver chain persists its live state, not the SKDM that created it.** `ReceiverChain` gained
144:  `to_state`/`from_state` (sealed as a `KeyMaterial` segment, ADR-010), because `next_iteration` and the
145:  skipped-key cache *are* the replay defence: rebuilding from the SKDM after a restart would reset the
149:  arrives before the key that opens it, so accepting an SKDM retries every content entry already stored
151:  this channel's default `ForwardOnly` history mode an SKDM released at the author's current position
153:  A second SKDM for a generation already held is ignored rather than rewinding the chain head.
154:- **The pairwise frame names its channel (M14.7d).** An SKDM is delivered inside an ADR-004 session, and a
157:  carries the channelID alongside the sealed message. It is not a secret (it is on the board and in the
159:  protects is weakened; the SKDM itself is unchanged.
[0m
Two verification checks remain — `NodeConfig` anchors handling, and the M17 serve gate:
[0m$ [0mrg -n "anchor" crates/vox-core/src/node/api.rs | head -20; echo ---; rg -n "anchor" crates/vox-core/src/node.rs | head; echo ---; rg -n "consent|grant|approve" crates/vox-core/tests/node_m17_serve_gate.rs | head -20; echo ---; rg -n "consent|grant" crates/vox-core/tests/node_m18_revocation_gate.rs | head -10
99:    /// anchors, whether or not it is a member — in channelID order. What an anchor
102:    pub anchoring: Vec<AnchoredChannel>,
129:    /// (`None` when it keeps none — a client's board, or an anchor not yet caught up).
175:    /// this node as anchor and responder. The link arrives as
340:    /// An invite link would not parse, or named a channel/anchor this node cannot
---
27:pub mod anchor;
---
6://! then granting him `dial:`. This gate is the same reachability with that step deleted.
100:fn m17_a_service_room_is_reached_with_no_grant_step() {
152:        // ---- `vox serve 22`: one command makes the room, the grant and the service ----
223:        // ---- and he reaches it, with no grant having been issued to anyone ----
244:            let msg = b"a room-bound service reached with no grant step";
---
2://! out, and it costs the members who keep consent nothing.
5://! Argon2id profile. Alice consents to Bob and Carol; all three read her message.
186:        // ---- consent to both, then one message all three can read ----
194:            assert!(out.is_done(), "Alice consents to {name}: {out:?}");
234:            "the one remaining consenter was re-keyed at once"
273:            "the rotation is invisible to whoever keeps consent: {carol_texts:?}"
[0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [limit=100, offset=1600][0m
One more check — how the join responder is chosen (for the auto-consent finding):
[0m
[0m$ [0mrg -n "version" Cargo.toml crates/vox-core/Cargo.toml crates/vox-tui/Cargo.toml 2>/dev/null | head -6; echo ---; rg -n "epoch" crates/vox-core/src/tunnel/session.rs | head -5; echo ---; rg -n "fn overlay_addr|pub fn" crates/vox-core/src/tunnel/addr.rs | head
crates/vox-tui/Cargo.toml:8:version.workspace = true
crates/vox-tui/Cargo.toml:10:rust-version.workspace = true
Cargo.toml:10:version = "0.1.0"
Cargo.toml:12:rust-version = "1.94"
Cargo.toml:18:# with the exact same primitive versions (ADR-003: deterministic, agile crypto).
Cargo.toml:22:zeroize = { version = "1", features = ["derive"] }
---
---
41:pub fn overlay_addr(composite_pubkey: &[u8; COMPOSITE_PUB_LEN]) -> Ipv6Addr {
55:pub fn verify_addr(claimed: &Ipv6Addr, composite_pubkey: &[u8; COMPOSITE_PUB_LEN]) -> bool {
[0m
# Review of ADR-017 third revision

## 1. The authorization model: sound core, one poisoned edge

The core gate is sound, and I want to say that plainly before attacking it. Under the new model the dial check runs **on the host's node** against `readers_of(host)` — a set resolved exclusively from `ConsentGrant`/`ConsentRevocation` entries the host itself signed (`governance/evaluator.rs:757-782`, single-writer, `evaluator.rs:158`). I tried every peer-influence path: forged grants (need the host's composite signature, `evaluator.rs:239`), key-swap per fingerprint (`node/channel.rs:1119-1127` refuses), stale-epoch replay (`in_effect`, `evaluator.rs:519-523`), withholding the host's own revocation from the host (impossible — it authors locally, `node/channel.rs:1490-1521`). Consent divergence between nodes is irrelevant to the gate because only the host's view is consulted. The claim that vouching becomes non-escalating is also correct: `learn_members` grows the *admitted-author* set (`node/actor.rs:2106-2118`), but authors ≠ readers, and nothing but the host's signature creates reader edges. The withdrawal of the genesis grant is right, and the withdrawn model really was the vulnerability the plan says it was (`evaluator.rs:386-399` confers `dial:` on every key in `authors.keys()`, `node/channel.rs:946-952`).

**The attack that remains.** There is one consent edge in every host's set that no human approved: **the join-time auto-consent to the responder**. When a node joins a channel it automatically releases its sender key to the responder and records a full `ConsentGrant` (`node/actor.rs:1758-1764`, `release_key_to` → `issue_consent`, `node/channel.rs:1311-1333`) — "part of joining rather than a separate consent decision" (actor.rs:1758-1760). Under decision 3, that edge *is* service reach. So:

1. Mallory holds the room passphrase (admission is passphrase + PoW — the plan's own words) or is a member.
2. Mallory hands Bob an invite link with `r=<Mallory>` (`node/link.rs:222`), or — with no `r=` — the responder is simply `set.members.first()` (`node/actor.rs:1603-1609`), i.e. **whichever member the anchor's board lists first**. A malicious anchor curates that.
3. Bob joins; his node auto-consents to Mallory. Bob made no decision about Mallory.
4. Bob later runs `vox serve <room> 22`, believing decision 4's output ("serving to 3 of 5 members — the 3 whose keys you have approved"). Mallory is in `readers_of(Bob)`; the M17.7 dial check passes; Mallory reaches `:22`.

This is exactly the class the ADR withdraws the genesis grant for: an authorization conferred by a non-human act, influenceable by a peer (the link-giver) and by the anchor (board ordering). It is narrower than the withdrawn bug — one silent edge per join, not the whole room — but it falsifies the plan's central sentence, "reachable by **exactly** the members its host has approved," for the *common* case under the new model, where the host joined a pre-existing room rather than creating one. M17.6 fixes `learn_members`/`admit_author`; nothing in M17.6–M17.11 touches `release_key_to`. The plan must either split the bootstrap release from reach-bearing consent (e.g. a bootstrap grant flavor excluded from the dial basis, promotable by `vox consent`) or accept the edge in writing. Note the release itself is load-bearing (the ADR-004 responder cannot speak until the joiner does), so "delete it" is not available — but reach need not follow the grant.

Secondary, stated-but-worth-naming: every *future* reading approval retroactively widens reach on every service ever bound to that room. Decision 3 blesses this, but decision 4's "3 of 5" line is then a snapshot that silently goes stale — the audience grows with each later `vox consent` with no service-side signal.

## 2. Decision 9's one-layer claim: right conclusion, false justification, and a feasibility problem

**The justification is false.** A party holding the descriptor, lacking approval, and knowing the name **exists by the plan's own design**: a revoked reader. Revocation does not remove membership (they keep the passphrase and keep syncing the log — they hold every new sealed descriptor), and they know the name from the last descriptor they could open. Likewise any unapproved member who reads a pasted name — and decision 9 itself declares pasting consequence-free, so unapproved members knowing names is an *expected* state. The single layer survives both anyway, because it is keyed to **reader keys** (Tor's *inner* construction), and knowing the name grants nothing against a reader-keyed wrapper. Tor needs its outer layer for parties who are *name-blind* (HSDirs reading metadata, linking descriptors across uploads); Vox's name-blind holders (anchor, unapproved members) already see only per-reader ciphertext. So: one layer is right; the sentence justifying it is wrong and should not survive into implementation as a load-bearing invariant someone might "preserve."

**The anchor specifically is not the counterexample.** It holds the descriptor (it keeps the whole channel log, `node/actor.rs:990-1019`; "stores ciphertext," `node/headless.rs:3-4`) and lacks approval (non-member by construction, actor.rs:991-993), but it does not know the name: the board carries only genesis/member records, the circuit `Open` frame names a peer fingerprint only (`node/circuitstream.rs:288-289`), and the name exists in the clear nowhere outside the envelope. What the anchor *does* get, and the plan's conceded "audience size visible" understates, is a **time series**: a new sealed entry of wrapper-count size on every `chain_id` advance, forever, per service, per room it anchors — update cadence and audience trajectory correlated with membership. Tor re-blinds per time period specifically to deny HSDirs this. Not content leakage; say it honestly or not at all.

**The feasibility problem is worse than the justification.** Decision 9 specifies "one wrapper per approved reader, under the ADR-006 per-recipient sealing the channel already uses for SKDMs," and the Consequences claim "Tor's client-auth property obtained from machinery the channel already has." That machinery does not exist. ADR-006's per-recipient sealing is `Skdm::seal_into` — encryption **into a live ADR-004 pairwise session**, per delivery (ADR-006 impl. notes; `node/pairwise_stream::deliver_skdm`). A descriptor published **on the log** must be openable later, offline, by a reader with no session to the host at publication time. That requires a *non-interactive* seal to the reader's static key — exactly Tor's `auth-client` construction (`x25519(service_sk, client_pk)` + KDF, `hs_descriptor.c:1425`), which is new crypto for Vox, new wire format, new key-management decisions (which reader key? identity root? forward secrecy of wrappers?). M17.10 is implementable, but it is **not** "no new mechanism at all," and "the sealing work is the SKDM distribution that already happens" is false — SKDM distribution is per-live-session; this is per-log-entry. Scope M17.10 accordingly.

## 3. `chain_id` vs channel epoch: the plan is right

Verified end to end. `revoke_consent` → `rotate_sender` → `SenderChain::rotated` increments `chain_id` (`node/channel.rs:1490-1521`, `group/state.rs:272-281`), and the revocation entry records `new_chain_id` (`governance/membership.rs:135-143`). The channel epoch advances **only** via authorized `PassphraseRotation` entries (`evaluator.rs:533-558`) — ADR-007 §Revocation says precisely this ("advancing `A`'s own `chain_id` … *not* the channel `epoch`," ADR-007:186-188). Decision 9's correction is sound and the recorded wrong premise is honestly kept.

**But decision 10 point 3 still says "republishes the descriptor without that reader's wrapper, on the epoch bump" (ADR-017:472).** That is the pre-revision counter, it contradicts decision 9 and the status header (ADR-017:19-20), and an implementer reading decision 10 will key republish to a counter that a revocation does not move — recreating the exact bug decision 9 was corrected to avoid. Internal contradiction; must be fixed.

Related and unaddressed: **approving** a reader does *not* advance `chain_id` (grants don't rotate, `node/channel.rs:1311-1333`), so a newly approved reader cannot open the standing descriptor until the next scheduled rotation or revocation. Decision 3's "takes effect immediately and needs no second act" is true for reach (dial-time check) and false for discovery; decision 4's "the host hands over nothing at all" fails for every reader approved after publication. The plan needs the sealed-name handoff specified, or republish-on-grant.

## 4. Decision 1's keypair: attack real, keypair works, dichotomy false

The republish attack is real against a bare label: the same name-string in two rooms with two descriptor signers is genuinely ambiguous (per-room binding context, nothing in the string), enabling a fake-host/MITM service for non-host-key-pinning protocols. The keypair does stop it structurally — a descriptor for `base32(pubkey)` must verify under that key. Two gaps: (a) the plan never actually states that the descriptor is signed **by the service key** and checked against the name — say it, it's the load-bearing check; (b) the "impossible rather than detectable" framing is a false dichotomy. **A cheaper construction also makes it impossible: bind the host key into the name** — `base32(label ‖ host_fingerprint)` (or its hash), descriptor signed by the host key named in the string. An attacker publishing in another room must then emit a *different string*; one string cannot have two hosts. No new keypair to persist, and it deletes the plan's own listed cost — "a service key is a new thing that can be lost … no recovery" (ADR-017:530-532, 250). The keypair remains defensible (Tor fidelity, name survives host-key rotation), but decision 1's "why the service's own keypair" section presents a necessity that does not exist.

## 5. "Not a bearer capability": true under the plan

Verified against the plan as written. M17.9's gate: "a name for a service this client holds no openable descriptor for does not resolve at all" — resolution requires an opened descriptor, so a pasted name plus no approval yields no host address, no dial, nothing. The dial gate is live consent, not string possession (decision 9, decision 10.4). For an approved reader of the *same host in another room*: their reach in that other room comes from being approved *there* (union semantics, decision 3), not from the string — the string adds nothing they didn't have. Even a member who bypasses discovery and dials the host directly from board records is refused at `session::accept`. This claim is sound. One caveat worth a sentence in the ADR: pasting the name where *room members* can see it breaks the decider's converse rule — "should not know it exists" — for every unapproved member who reads the paste. No reach leaks; existence does. "Without consequence" overstates.

## 6. The plan's account of what ships: two claims true, two false

**True.** v0.1.0 implements the withdrawn model: `GenesisBody::service_grant` (`genesis.rs:232`), `create_with_grant` (`genesis.rs:387`), `Evaluator::build_with_members(authors.keys())` (`node/channel.rs:946-952`), `service_grant_verdict` over the local member set (`evaluator.rs:386-399`), `serve_room` minting a room with a `dial:` grant (`actor.rs:2583-2591`), `vox grant` (`cli.rs:399`, `actor.rs:2713`), `0x0013` (`servicegrant.rs`). And the M17.3 gate does assert the vulnerability: `node_m17_up_gate.rs:118-143` builds the evaluator over `[guest_fp]` against the genesis grant with no certificate, exactly as the plan quotes. Both verified.

**False.** (a) The status line "Decisions 5, 6 and 7 are built and shipped in v0.1.0 (`node::up`, `node::resolver`, `<config_dir>/anchors`)" and M17.4 "stands. Anchors as configuration" — **there is no `<config_dir>/anchors` anywhere in the tree.** Anchors come only from `--anchor`/`VOX_ANCHORS` (`cli.rs:48-49`) and per-channel `SEG_ANCHORS` learned from invite links (`actor.rs:1112-1123`). `vox node` writes a key file, not an anchor spec (`headless.rs:38-56`). Decision 7 is proposed, not built; M17.4 is work, not a stand. (b) ADR-013's amendment claims the anchor gate was "**Rewritten 2026-09-21** … the gate previously drove `Alice grants dial:ssh`, which no longer exists" (ADR-013:240-243) — the tree's `node_m15_anchor_gate.rs:660-670` still drives exactly that grant, and `vox grant` still exists. ADR-013:235 and ADR-007:5 likewise narrate the withdrawal in the past tense ("is withdrawn", "0x0013 is retired") while ADR-017 honestly says none of it is built. Anyone reading ADR-013/007 alone would believe the vulnerability is closed. The amendments must be prospective or the tree must match; as written, two of the three documents misstate the security posture of shipped code.

## 7. What is missing entirely

- **No descriptor retraction.** Log entries are durable; there is no tombstone, no un-publish, no "host stopped offering." A host that closes the room (dials then die — `host_snapshot` only covers open channels, `actor.rs:2856-2872`) leaves a standing sealed descriptor on every member's log forever: `vox service list` shows a dead service, dials fail opaquely. `remove_service` removes local bind config, not the published descriptor.
- **Host eviction does not kill the service.** The only removal in ADR-007 is passphrase rotation. `TunnelRequest` carries `(channel_id, service_tag)` and **no epoch** (`tunnel/session.rs:51-56`), so a host rotated-against keeps serving from its frozen pre-rotation state (its evaluator still contains its own old-epoch consent edges, `evaluator.rs:519-523` keeps them in-effect *at that epoch*) to any member who can still reach its endpoint. The room evicted the host; the host's service gate is the host's own consent, so nothing turns it off. The plan never defines "members of that room" for a post-rotation host, nor says the service dies.
- **Service-key identity rule unspecified.** "Persisted per service in the profile directory" — per room? per `(room, port)`? per local endpoint? Decision 3's "a service bound to two rooms … the name is stable across them" requires one identity rule that makes `vox serve A 22` and `vox serve B 22` the *same* service; nothing says how. Two hosts binding the same port in one room is implicitly fine (two keypairs, two names) but the plan never says so.
- **`vox up` is incoherent with per-service names.** `UpArgs` takes one room (`cli.rs:333-341`); `bring_up` builds the resolver from that one channel's genesis (`actor.rs:2767-2774`). But names are per-service and cross-room, and decision 5 promises one `ProxyCommand` "written once for every room there will ever be" pointing at one proxy. A per-room proxy cannot resolve other rooms' names; the resolver must span every descriptor this client can open, and `vox up` should take no room argument. M17.3's correction (name → descriptor) doesn't touch this. `vox forward` survives coherently (dials `(channel, port)`, host checks consent).
- **Bind authorization is orphaned.** `add_service` checks `can_bind` (`node/channel.rs:1232-1234`). Today `bind:` comes from the genesis grant or `vox grant --may-bind`. The plan deletes **both** and never re-specifies what authorizes offering a service. Post-M17.7 the only remaining bind source is the genesis creator's `admin` (root admin implies all, `evaluator.rs:646-647`) — `vox serve <room> 22` by any member who didn't create the room fails. Either binding one's own port is the host's own business (delete the check — consistent with "reach is consent") or the plan must say what confers it. As written, M17.7 breaks the verb it reshapes.

## 8. Deleting `vox grant`

The core call is right: a second authorization surface that can drift from consent is the bug class behind findings #1 and #5, and one surface cannot disagree with itself. Two uses are genuinely unconsidered:

- **Temporal scoping.** `vox grant --days` carried expiry (`cli.rs:289-291`). Consent has no expiry — reach is permanent until revoked, and revoking *only* reach is impossible (it cuts reading too) and costs a sender-key rotation plus O(members) re-key (`node/channel.rs:1490-1521`, `actor.rs:1899-1959`). A host who wants week-long SSH access for a contractor must either remember to revoke-and-cut-chat or spin up a parallel room. The plan states the narrowing trade but never notices it also deleted time-bounding.
- **`--may-bind`** was the only non-admin source of `bind:`; see the orphaned-bind finding above — deleting `vox grant` without replacing bind authorization breaks `vox serve` for non-creators.

## What the plan gets right (no objections manufactured)

The withdrawal of the genesis grant and `0x0013` is correct and the vulnerability was real as described; the three-way analysis of step six is honest; the `chain_id` correction (Q3) is right and well-evidenced; the non-bearer-capability claim (Q5) is right; the vouching-is-separate-and-non-escalating claim is right; the host-local, single-writer gate is sound against peer influence *except* the responder edge; decision 6's account of the carried session matches the architecture (`session.rs:251-274` authorizes before any local connect; circuit frames carry fingerprints only); the Tor citations are accurate (`hs_common.c` `hs_build_address` ≈:902; `hs_descriptor.c:9-52` layering, `:712` auth-client lines, `:1425` `KEYS = KDF(subcredential ‖ x25519(sk, pk))`, 180-minute lifetime); the M17.3-gate and v0.1.0 accounts are accurate.

---

## VERDICT

**REVISE** — implementable once these are fixed, in priority order:

1. **Close or explicitly accept the join-responder auto-consent edge** (`actor.rs:1758-1764`, responder selection `actor.rs:1603-1609`). It falsifies "reach == the host's approved readers," is issued with no human act, and the choice of recipient is influenceable by the link-giver and by a malicious anchor's board ordering. Split the bootstrap SKDM release from reach-bearing consent, or document the edge as accepted.
2. **Specify the non-interactive per-reader wrapper for M17.10** and delete the "machinery the channel already has / sealing work is the SKDM distribution" claims — ADR-006's sealing is live-session-based; a log-published, open-later wrapper is new crypto (Tor's `auth-client` construction). Rescope M17.10.
3. **Fix decision 10 point 3** ("on the epoch bump", ADR-017:472) to `chain_id` — it contradicts decision 9 and reintroduces the corrected bug.
4. **Resolve the discovery-latency contradiction**: approval does not advance `chain_id`, so newly approved readers cannot open the standing descriptor; specify the sealed-name handoff or republish-on-grant.
5. **Specify what authorizes `bind:`** after both sources are withdrawn, or `vox serve` works only for room creators.
6. **Define the service-key identity rule** (per room / `(room, port)` / endpoint) and state the two-hosts-one-port case.
7. **Specify descriptor retraction and the host-eviction interaction** (`TunnelRequest` carries no epoch; a rotated-against host keeps serving its frozen consent set).
8. **Make `vox up`/the resolver span all joined rooms** — per-room proxy + per-service names + one ProxyCommand is incoherent as specified.
9. **Correct the false shipped-today claims**: decision 7 / M17.4 anchors-as-config is not built; ADR-013/007 amendments narrate unbuilt withdrawal in the past tense (M15 gate still drives `vox grant`).
10. Optionally, note the cheaper `label ‖ host-key` name construction in decision 1 and state explicitly that descriptors are signed by the service key named in the string.
