[0m
> build · kimi-k3
[0m
[0m→ [0mRead docs/adr/ADR-017-room-bound-services.md
[0m→ [0mRead docs/adr/ADR-013-overlay-tunneling.md
[0m→ [0mRead docs/adr/ADR-007-membership-consent-and-admin-governance.md
[0m✗ [0mRead crates/vox-core/src/governance/channel.rs failed
[91m[1mError: [0mFile not found: crates/vox-core/src/governance/channel.rs
[0m→ [0mRead crates/vox-core/src/governance/servicegrant.rs
[0m
[0m$ [0mls -la crates/vox-core/src/governance/ crates/vox-core/src/node/ crates/vox-core/src/tunnel/ 2>&1
crates/vox-core/src/governance/:
total 528
drwxr-xr-x@ 15 robert.lee  wheel    480 Sep 21 16:32 .
drwxr-xr-x@ 33 robert.lee  wheel   1056 Sep 21 16:32 ..
-rw-r--r--@  1 robert.lee  wheel  12134 Sep 21 16:32 capability.rs
-rw-r--r--@  1 robert.lee  wheel  19183 Sep 21 16:32 cert.rs
-rw-r--r--@  1 robert.lee  wheel  13453 Sep 21 16:32 consent.rs
-rw-r--r--@  1 robert.lee  wheel  12914 Sep 21 16:32 entry.rs
-rw-r--r--@  1 robert.lee  wheel  47602 Sep 21 16:32 evaluator.rs
-rw-r--r--@  1 robert.lee  wheel  23475 Sep 21 16:32 genesis.rs
-rw-r--r--@  1 robert.lee  wheel   5720 Sep 21 16:32 invite.rs
-rw-r--r--@  1 robert.lee  wheel   6104 Sep 21 16:32 membership.rs
-rw-r--r--@  1 robert.lee  wheel  14087 Sep 21 16:32 policy.rs
-rw-r--r--@  1 robert.lee  wheel   8560 Sep 21 16:32 rotation.rs
-rw-r--r--@  1 robert.lee  wheel   7619 Sep 21 16:32 servicegrant.rs
-rw-r--r--@  1 robert.lee  wheel  70552 Sep 21 16:32 vectors.rs
-rw-r--r--@  1 robert.lee  wheel   3433 Sep 21 16:32 visibility.rs

crates/vox-core/src/node/:
total 1072
drwxr-xr-x@ 24 robert.lee  wheel     768 Sep 21 16:32 .
drwxr-xr-x@ 33 robert.lee  wheel    1056 Sep 21 16:32 ..
-rw-r--r--@  1 robert.lee  wheel  130897 Sep 21 16:32 actor.rs
-rw-r--r--@  1 robert.lee  wheel   12703 Sep 21 16:32 anchor.rs
-rw-r--r--@  1 robert.lee  wheel   18887 Sep 21 16:32 api.rs
-rw-r--r--@  1 robert.lee  wheel   91745 Sep 21 16:32 channel.rs
-rw-r--r--@  1 robert.lee  wheel   17922 Sep 21 16:32 circuitstream.rs
-rw-r--r--@  1 robert.lee  wheel    2567 Sep 21 16:32 content.rs
-rw-r--r--@  1 robert.lee  wheel   22392 Sep 21 16:32 coordstream.rs
-rw-r--r--@  1 robert.lee  wheel    2843 Sep 21 16:32 headless.rs
-rw-r--r--@  1 robert.lee  wheel   26195 Sep 21 16:32 joinstream.rs
-rw-r--r--@  1 robert.lee  wheel   14949 Sep 21 16:32 link.rs
-rw-r--r--@  1 robert.lee  wheel   18006 Sep 21 16:32 net.rs
-rw-r--r--@  1 robert.lee  wheel   43668 Sep 21 16:32 network.rs
-rw-r--r--@  1 robert.lee  wheel    8273 Sep 21 16:32 pairwise_stream.rs
-rw-r--r--@  1 robert.lee  wheel    4556 Sep 21 16:32 passphrase.rs
-rw-r--r--@  1 robert.lee  wheel    5560 Sep 21 16:32 paths.rs
-rw-r--r--@  1 robert.lee  wheel   26219 Sep 21 16:32 prekeys.rs
-rw-r--r--@  1 robert.lee  wheel    9130 Sep 21 16:32 profile.rs
-rw-r--r--@  1 robert.lee  wheel    6012 Sep 21 16:32 resolver.rs
-rw-r--r--@  1 robert.lee  wheel   13074 Sep 21 16:32 store.rs
-rw-r--r--@  1 robert.lee  wheel    6374 Sep 21 16:32 syncstream.rs
-rw-r--r--@  1 robert.lee  wheel    7281 Sep 21 16:32 tunnel.rs
-rw-r--r--@  1 robert.lee  wheel    8373 Sep 21 16:32 up.rs

crates/vox-core/src/tunnel/:
total 128
drwxr-xr-x@  8 robert.lee  wheel    256 Sep 21 16:32 .
drwxr-xr-x@ 33 robert.lee  wheel   1056 Sep 21 16:32 ..
-rw-r--r--@  1 robert.lee  wheel   2688 Sep 21 16:32 addr.rs
-rw-r--r--@  1 robert.lee  wheel   4111 Sep 21 16:32 authz.rs
-rw-r--r--@  1 robert.lee  wheel   9157 Sep 21 16:32 service.rs
-rw-r--r--@  1 robert.lee  wheel  12483 Sep 21 16:32 session.rs
-rw-r--r--@  1 robert.lee  wheel   7275 Sep 21 16:32 socks.rs
-rw-r--r--@  1 robert.lee  wheel  14961 Sep 21 16:32 sshca.rs
[0m
[0m✱ [0mGlob "crates/vox-core/src/governance/**"[90m 13 matches[0m
[0m→ [0mRead crates/vox-core/src/governance/genesis.rs
[0m→ [0mRead crates/vox-core/src/governance/consent.rs
[0m→ [0mRead crates/vox-core/src/governance/evaluator.rs
[0m✱ [0mGrep "build_evaluator|build_with_members|readers_of"[90m in crates · 25 matches[0m
[0m→ [0mRead crates/vox-core/src/node/channel.rs[90m [offset=700, limit=400][0m
[0m→ [0mRead crates/vox-core/src/node/channel.rs[90m [offset=1100, limit=450][0m
[0m→ [0mRead crates/vox-core/src/node/channel.rs[90m [offset=1550, limit=400][0m
[0m→ [0mRead crates/vox-core/src/node/resolver.rs
[0m→ [0mRead crates/vox-core/src/node/up.rs
[0m→ [0mRead crates/vox-core/src/tunnel/session.rs
[0m→ [0mRead crates/vox-core/src/node/link.rs
[0m✱ [0mGrep "learn_members|admit_author|fn serve_tunnel|node_m17_up_gate"[90m in crates · 11 matches[0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [offset=2020, limit=200][0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [offset=1380, limit=120][0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [offset=1680, limit=120][0m
[0m✱ [0mGrep "StreamKind::Tunnel|snapshot|fn serve"[90m in crates/vox-core/src/node/actor.rs · 44 matches[0m
[0m→ [0mRead crates/vox-core/src/node/tunnel.rs
[0m→ [0mRead crates/vox-core/tests/node_m17_up_gate.rs
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [offset=1290, limit=90][0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [offset=2560, limit=160][0m
[0m✱ [0mGrep "fn verify"[90m in crates/vox-core/src/node/prekeys.rs · 0 matches[0m
[0m✱ [0mGrep "impl MemberBundleRecord|fn verify\("[90m in crates/vox-core/src · 26 matches[0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [offset=2720, limit=180][0m
[0m→ [0mRead crates/vox-core/src/nat/record.rs[90m [offset=400, limit=280][0m
[0m→ [0mRead crates/vox-core/src/node/actor.rs[90m [offset=2900, limit=210][0m
[0m✱ [0mGrep "consent|Consent|revoke|approve"[90m in crates/vox-tui/src/cli.rs · 54 matches[0m
[0m→ [0mRead crates/vox-tui/src/cli.rs
[0m
[0m$ [0mls /opt/tor/src/feature/hs/ 2>&1 | head -30
feature_hs.md
hs_cache.c
hs_cache.h
hs_cell.c
hs_cell.h
hs_circuit.c
hs_circuit.h
hs_circuitmap.c
hs_circuitmap.h
hs_client.c
hs_client.h
hs_common.c
hs_common.h
hs_config.c
hs_config.h
hs_control.c
hs_control.h
hs_descriptor.c
hs_descriptor.h
hs_dos.c
hs_dos.h
hs_ident.c
hs_ident.h
hs_intropoint.c
hs_intropoint.h
hs_metrics_entry.c
hs_metrics_entry.h
hs_metrics.c
hs_metrics.h
hs_ob.c
[0m
[0m→ [0mRead crates/vox-core/src/node/anchor.rs
Now let me check the Tor reference implementation and the anchor code.
[0m→ [0mRead crates/vox-core/src/tunnel/authz.rs
[0m→ [0mRead crates/vox-core/src/tunnel/service.rs
[0m✱ [0mGrep "config_dir.*anchors|anchors.*config|ANCHORS_FILE|anchors\b"[90m in crates/vox-core/src/node/paths.rs · 100 matches[0m
Now let me check the tunnel authz/service modules, the SKDM sealing construction, and the anchors-config claim.
[0m
[0m$ [0mgrep -rn "anchors" crates/vox-core/src/node/paths.rs crates/vox-tui/src/app.rs 2>/dev/null | head -30; echo ---; grep -rln "config_dir" crates/vox-core/src/ | head; echo ---; grep -rn "\"anchors\"\|anchors_file\|ANCHORS" crates/vox-tui/src/*.rs | head -20
crates/vox-tui/src/app.rs:263:    anchors: vox_core::nat::bootstrap::BootstrapSet,
crates/vox-tui/src/app.rs:274:        .anchors(anchors)
crates/vox-tui/src/app.rs:314:    anchors: vox_core::nat::bootstrap::BootstrapSet,
crates/vox-tui/src/app.rs:322:        .anchors(anchors);
---
crates/vox-core/src/node/paths.rs
---
crates/vox-tui/src/cli.rs:46:    /// `<fingerprint>@<multiaddr>` (repeatable; `VOX_ANCHORS` takes a comma-separated
crates/vox-tui/src/cli.rs:48:    #[arg(long = "anchor", env = "VOX_ANCHORS", value_delimiter = ',')]
crates/vox-tui/src/cli.rs:446:        anchors: std::env::var("VOX_ANCHORS")
[0m
[0m→ [0mRead crates/vox-core/src/group/skdm.rs[90m [offset=1, limit=120][0m
[0m
[0m$ [0msed -n '890,940p' /opt/tor/src/feature/hs/hs_common.c; echo '=== hs_descriptor.c:1-60 ==='; sed -n '1,60p' /opt/tor/src/feature/hs/hs_descriptor.c; echo '=== hs_descriptor.c:700-730 ==='; sed -n '700,730p' /opt/tor/src/feature/hs/hs_descriptor.c; echo '=== hs_descriptor.c:1400-1450 ==='; sed -n '1400,1450p' /opt/tor/src/feature/hs/hs_descriptor.c
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
=== hs_descriptor.c:1-60 ===
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
=== hs_descriptor.c:700-730 ===
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
=== hs_descriptor.c:1400-1450 ===
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

  tor_assert(subcredential);
  tor_assert(sk);
  tor_assert(pk);
  tor_assert(keys_out);

  keystream = tor_malloc_zero(keystream_len);

  /* Calculate x25519(sk, pk) to get the secret seed. */
  curve25519_handshake(secret_seed, sk, pk);
[0m
Now the Tor reference implementation at the cited lines.
[0m✱ [0mGrep "vox\.invalid|SNI"[90m in crates/vox-core/src · 3 matches[0m
[0m✱ [0mGrep "anchors"[90m in crates/vox-core/src/node/paths.rs · 100 matches[0m
[0m✱ [0mGrep "write.*anchor|anchor.*write|config.*anchor|save_anchor|persist_anchor"[90m in crates · 12 matches[0m
Let me verify decision 7's anchors-as-config claim and the SNI constant, then check the m15 gate's rewritten form and the prekeys/board serving policy.
[0m
[0m$ [0mgrep -n "anchors" crates/vox-tui/src/app.rs | head -30; echo ===; grep -rn "paths::Paths\|config_dir\|anchors_file\|fn anchors" crates/vox-core/src/node/paths.rs | head -20
263:    anchors: vox_core::nat::bootstrap::BootstrapSet,
274:        .anchors(anchors)
314:    anchors: vox_core::nat::bootstrap::BootstrapSet,
322:        .anchors(anchors);
zsh:1: == not found
[0m
[0m→ [0mRead crates/vox-core/src/node/paths.rs
[0m→ [0mRead crates/vox-tui/src/app.rs[90m [offset=255, limit=120][0m
[0m
[0m$ [0mgrep -rn '"anchors"' crates/ --include='*.rs' | head; echo ===; grep -rn 'join("anchors")\|/anchors\|anchors_path\|read_to_string.*anchor\|load.*anchors\|read.*anchors' crates/ --include='*.rs' | head -20
crates/vox-core/src/node/actor.rs:168:            .field("anchors", &self.anchors.len())
zsh:1: == not found
[0m
[0m$ [0mgit log --oneline -15; echo ===; git status --short | head -20; echo ===; git diff HEAD --stat | tail -5
00d0d37 docs(adr): withdraw capability-bearing rooms — services are consent-bound (ADR-017 third revision)
3b8da58 merge: review/independent-security-round (3-model review; ADR-009 C4 refuted, codec deadlock fixed, ADR-019 answered)
fb64378 review: independent security review round — evidence, corrections, one forced fix
7853179 merge: feat/adr009-wire-codec (ADR-009 blocker 2 closed)
b0c666d feat(deniable): ADR-009 blocker (2) — the dgka-setup (0x000B) wire codec
55c1f65 merge: feat/m15-sessions-from-bundles (ADR-016 sessions from bundle records)
5e7c5bd feat(node): M15 — members open sessions from bundle records, not only on the join path
875e2f8 merge: fix/macos-deployment-target (pin the macOS floor at 11.0)
150c7de fix(release): pin the macOS floor at 11.0 instead of inheriting rustc's defaults
8b4686e docs: whitelist, not allow-list
5d80f08 fix(ci): install the shells the proofs measure; stop fail-fast hiding macOS
b219630 fix(update): MAX_SIGNING_INFO_BYTES is macOS-only, like the code that reads it
bbc2b1b merge: fix/test-watchdog (a hung proof is a failing proof)
e94b3aa fix(tests): a hung proof is a failing proof — process watchdog + CI bounds
88dbd68 merge: fix/codesign-identifier (us.vox.cli)
zsh:1: == not found
[0m
[0m$ [0mgrep -rn 'anchors' crates/vox-core/src/node/headless.rs crates/vox-core/src/node/profile.rs 2>/dev/null | head; echo "---"; grep -rn 'config_dir' crates/vox-tui/src/ | head
---
crates/vox-tui/src/cli.rs:36:    pub config_dir: Option<PathBuf>,
crates/vox-tui/src/cli.rs:58:            self.config_dir.as_deref(),
crates/vox-tui/src/cli.rs:442:        config_dir: std::env::var_os("VOX_CONFIG_DIR").map(PathBuf::from),
[0m
[0m→ [0mRead crates/vox-core/tests/node_m15_anchor_gate.rs[90m [offset=1, limit=120][0m
[0m
[0m$ [0mgrep -n 'Grant\|grant\|Consent\|consent\|dial\|Dial\|approve' crates/vox-core/tests/node_m15_anchor_gate.rs | head -40
(no output)
[0m
[0m$ [0mgrep -rn 'TunnelServed\|ServiceAdd\|service_add\|AddService\|Forward\|tunnel' crates/vox-core/tests/node_m15_anchor_gate.rs | head -30; echo "---"; ls crates/vox-core/tests/ | head -50
crates/vox-core/tests/node_m15_anchor_gate.rs:511:/// tunnel is nothing more than TCP over a tunnel — grants Bob the capability to dial
crates/vox-core/tests/node_m15_anchor_gate.rs:520:#[ignore = "production Argon2id, a relayed join and a tunneled TCP round trip: ~15 s in release"]
crates/vox-core/tests/node_m15_anchor_gate.rs:532:        let service_addr = service.local_addr().unwrap();
crates/vox-core/tests/node_m15_anchor_gate.rs:582:            .apply(NodeCommand::AddService {
crates/vox-core/tests/node_m15_anchor_gate.rs:585:                local: service_addr,
crates/vox-core/tests/node_m15_anchor_gate.rs:593:        assert_eq!(offered, vec![("ssh".to_owned(), service_addr)]);
crates/vox-core/tests/node_m15_anchor_gate.rs:631:            .apply(NodeCommand::Forward {
crates/vox-core/tests/node_m15_anchor_gate.rs:640:            NodeEvent::Forwarding { local, .. } => Some(local),
crates/vox-core/tests/node_m15_anchor_gate.rs:656:            .apply(NodeCommand::StopForward { local: dark })
crates/vox-core/tests/node_m15_anchor_gate.rs:676:                    .apply(NodeCommand::Forward {
crates/vox-core/tests/node_m15_anchor_gate.rs:685:                    NodeEvent::Forwarding { local, .. } => Some(local),
crates/vox-core/tests/node_m15_anchor_gate.rs:704:                let _ = bob.apply(NodeCommand::StopForward { local }).await;
crates/vox-core/tests/node_m15_anchor_gate.rs:709:        .expect("the grant synced and the tunnel carried real bytes");
---
atrest_profile_floor.rs
nat_holepunch_through_nat.rs
node_m13_gate.rs
node_m14_gate.rs
node_m15_anchor_gate.rs
node_m15_session_from_bundle_gate.rs
node_m17_serve_gate.rs
node_m17_up_gate.rs
node_m18_revocation_gate.rs
support
watchdog_proof.rs
[0m
[0m→ [0mRead crates/vox-core/tests/node_m15_anchor_gate.rs[90m [offset=500, limit=215][0m
[0m
[0m$ [0mgit show --stat HEAD | head -40
commit 00d0d376e265045ec0958b0d08bc284d2d7ea756
Author: Robert E. Lee <robert@loveathome.us>
Date:   Mon Sep 21 16:40:17 2026 +0200

    docs(adr): withdraw capability-bearing rooms — services are consent-bound (ADR-017 third revision)
    
    ADR-017 decision 3 held that "'may this member dial it' and 'is this person a
    member' are the same question, asked once." That is refuted, and it is verified
    finding #1: admission to a room is a passphrase and a proof of work, not a human
    decision, so any party holding an address and a passphrase — or, through the
    vouching path, any party a single member syncs — was authorized to dial every
    service bound to that room.
    
    Authorization is now the host's ADR-007 per-sender consent set: a service bound
    to a room is reachable by exactly the members that host approved to read its
    messages there, and by nobody else. This removes the ADR's original sixth step
    without adding any mechanism, because the approval already existed and is a
    deliberate human act; the withdrawn model removed the step by delegating it to
    whoever held the passphrase.
    
    Withdrawn: GenesisBody::service_grant, service-grant-exclusion (0x0013, wire tag
    retired and not reused), `vox grant`, and `vox serve` creating rooms.
    
    The .vox name becomes the service's own persisted keypair, following Tor's
    construction (/opt/tor hs_common.c:902) rather than the channelID. That
    decoupling is what lets a service in a chat room have a name at all — resolver.rs
    resolves a name to the room's genesis creator, so it deliberately refuses every
    room `vox serve` did not create. One name, many ports (Tor's HiddenServicePort
    shape).
    
    Discovery becomes a Tor client-authorized descriptor with the room's log in place
    of the HSDir ring: one sealed envelope per (service, room), a per-reader wrapper
    each, exactly as hs_descriptor.c:712 emits one auth-client line per authorized
    client. One layer, not Tor's two — Vox's carrier is the room's own log rather
    than a stranger's disk, so the name travels inside the same envelope as the reach
    information. Consequence recorded as a property: a .vox name is not a bearer
    capability and can be pasted into a bug report without consequence.
    
    Freshness is keyed to the host's ADR-006 chain_id, not the channel epoch. The
    decision was first taken on my wrong premise that revocation bumps the epoch;
[0m
[0m$ [0mgit show --stat HEAD | tail -20
reversal is the substance of this change. node_m15_anchor_gate must be rewritten:
    its transition is now Alice approving Bob's key rather than Alice granting
    dial:ssh, which proves the same dark-service property from a single human act.
    
    ADR-007: 0x0013 struck, and per-sender consent recorded as load-bearing for reach
    as well as readability.
    
    Status is honest about what ships: v0.1.0 implements the withdrawn model, so
    decisions 1, 3, 4, 9 and 10 are proposed and not built, and the M17.3 gate
    currently asserts the vulnerability ("a real ADR-007 evaluator against the
    genesis service grant with no certificate issued to anybody") and must be
    rewritten rather than extended. Plan adds M17.6–M17.11.
    
    No code changes; the implementation follows per the house rule that the plan
    lands with the work it governs.

 ...-007-membership-consent-and-admin-governance.md |  16 +-
 docs/adr/ADR-013-overlay-tunneling.md              |  80 ++-
 docs/adr/ADR-017-room-bound-services.md            | 714 ++++++++++++---------
 3 files changed, 458 insertions(+), 352 deletions(-)
[0m
[0m$ [0mls crates/vox-core/tests/ | grep -i vouch; echo "---"; grep -rn 'chain_id' docs/adr/ADR-006*.md | head -20
---
docs/adr/ADR-006-group-messaging-sender-keys.md:67:- **SKDM fields:** `{ channelID, epoch, author_id, chain_id, iteration, chain_key, signing_pubkey,
docs/adr/ADR-006-group-messaging-sender-keys.md:68:  algo_ids, signature }`. The **`chain_id` is a per-sender generation identifier distinct from the
docs/adr/ADR-006-group-messaging-sender-keys.md:71:- **Message header:** `{ channelID, epoch, author_id, chain_id, iteration }`, all bound into the
docs/adr/ADR-006-group-messaging-sender-keys.md:75:  value for `(author_id, chain_id)`; cache a **bounded** set of skipped per-iteration message keys
docs/adr/ADR-006-group-messaging-sender-keys.md:78:  (new `chain_id`) on every membership change affecting it (revocation, ADR-007) and additionally on a
docs/adr/ADR-006-group-messaging-sender-keys.md:81:- **Compromise recovery:** because there is no self-heal, recovery is an explicit `chain_id` rotation
docs/adr/ADR-006-group-messaging-sender-keys.md:105:- **SKDM (tag `0x0002`, `vox/skdm/v1`)** is the canonical body `[cid, epoch, author_id, chain_id,
docs/adr/ADR-006-group-messaging-sender-keys.md:111:  bound as AEAD associated data (`vox/group-msg-ad/v1 ‖ cbor[cid, epoch, author_id, chain_id,
[0m
[0m$ [0msed -n '60,90p' docs/adr/ADR-006-group-messaging-sender-keys.md
(no output)
[0m
[0m$ [0msed -n '55,95p' "docs/adr/ADR-006-group-messaging-sender-keys.md"
- **Full-history channels (the default, ADR-014):** consent releases the sender's **origin SKDM
  (`iteration = 0`) for each epoch the retained history spans** → the newcomer derives the whole chain
  and reads all of that sender's retained history. Senders keep their per-epoch origin chain keys for
  this purpose, bounded by channel TTL (ADR-010).
History is therefore **per-sender and consent-gated exactly like live messages**: a member who never
consents reveals no history, and "full history" never bypasses per-sender consent.

**PCS via explicit rotation.** Base Sender Keys has only weak post-compromise security and does
not self-heal (Balbás et al., ASIACRYPT 2023). Recovery and revocation rely on *explicit* sender-
key rotation and passphrase-epoch rotation (ADR-007), not on ratchet self-healing.

**Wire format & operational rules (so the group layer is buildable):**
- **SKDM fields:** `{ channelID, epoch, author_id, chain_id, iteration, chain_key, signing_pubkey,
  algo_ids, signature }`. The **`chain_id` is a per-sender generation identifier distinct from the
  channel `epoch`** — it increments on every per-member sender-key rotation (revocation, scheduled
  refresh) so multiple generations are unambiguous within one epoch.
- **Message header:** `{ channelID, epoch, author_id, chain_id, iteration }`, all bound into the
  AEAD associated data; receivers reject a message whose `(channelID, epoch)` does not match the
  expected channel (the cross-group-confusion guard).
- **Replay / window:** accept a message only if its `iteration` advances the receiver's last-seen
  value for `(author_id, chain_id)`; cache a **bounded** set of skipped per-iteration message keys
  for out-of-order delivery (same `MAX_SKIP` discipline as ADR-004); reject beyond the bound.
- **Rotation cadence (concrete defaults, channel-policy-tunable):** a sender rotates its sender key
  (new `chain_id`) on every membership change affecting it (revocation, ADR-007) and additionally on a
  scheduled bound — **default max `N` = 1000 messages or max `T` = 7 days, whichever first** — to cap
  the post-compromise exposure window; passphrase-epoch rotation supersedes all per-sender chains.
- **Compromise recovery:** because there is no self-heal, recovery is an explicit `chain_id` rotation
  redistributed to current consenters (ADR-007); the schedule above bounds how long a leaked sender
  key remains useful.

## Consequences

### Positive
- Per-author key model makes per-sender consent (ADR-007) natural — the headline differentiator.
- Efficient one-to-many broadcast; channel-scoped fits the ADR-001 model exactly.
- Vindicates choosing Sender Keys over MLS for *this* product's trust model.

### Negative
- Weak PCS inherent to Sender Keys; mitigated only by explicit rotation (a chatty operation as
  membership churns).
- Larger PQ keys increase SKDM size and distribution cost (O(recipients) per rotation).
[0m
[0m$ [0mgrep -n 'approved\|consent\|audience\|members' crates/vox-tui/src/tunnel_cli.rs | head -20; echo "---"; sed -n '1,40p' crates/vox-core/tests/node_m17_serve_gate.rs
228:    let members: Vec<Digest32> = view
232:        .map(|d| d.members.clone())
234:    let target = resolve_prefix(member_prefix, &members)?;
266:    let members: Vec<Digest32> = view
270:        .map(|d| d.members.clone())
272:    let host = resolve_prefix(host_prefix, &members)?;
---
//! ADR-017 **M17.2 gate** — the two-command flow, with the third step *absent*.
//!
//! The M16.1 gate proved the mechanism: a TCP service reached across the overlay
//! between two clients behind symmetric NATs, through the user's own anchor. It needed
//! six steps, and the worst of them was the sixth — Alice waiting for Bob to appear and
//! then granting him `dial:`. This gate is the same reachability with that step deleted.
//!
//! So the central assertion here is a **negative**: nowhere does this test issue
//! `GrantTunnel`, or any certificate, to anybody. Bob reaches Alice's service because
//! her room's genesis says members may (ADR-017 decision 3), and he became a member by
//! holding the passphrase and paying the proof of work.
//!
//! It also proves the two things the host needs and the service cannot give:
//! - the room's **`.vox` hostname** is derivable from the address Bob was handed, with
//!   no extra field anywhere — the same 52 characters begin both;
//! - a **`TunnelServed` event** names who reached what, because `sshd` behind a Vox
//!   tunnel only ever logs `127.0.0.1` (ADR-017 decision 6).
//!
//! Everything goes through the client API. Production Argon2id; the ADR-005 PoW is
//! reduced, because what is under test is the flow and the M14 gate already runs the
//! production solve. `#[ignore]`d in the debug suite, run by CI's release step.

#[path = "support/watchdog.rs"]
mod watchdog;

#[path = "support/vnet.rs"]
mod vnet;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use vnet::{NatKind, VirtualNet};
use vox_core::join::pow::PowParams;
use vox_core::nat::bootstrap::{BootstrapNode, BootstrapSet};
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::link::{b32_encode, channel_of_hostname, vox_hostname};
use vox_core::node::paths::Paths;
[0m
[0m✱ [0mGrep "should_rotate_sender|rotate_sender|deliver_rekeys_for"[90m in crates/vox-core/src/node · 9 matches[0m
Let me check where scheduled rotation is triggered and confirm the revocation gate's behavior.
[0m
[0m$ [0mgrep -rn 'config_dir' crates/vox-core/src/ | grep -vi test | head -20; echo "---"; grep -rn 'anchors' crates/vox-tui/src/tunnel_cli.rs | head
crates/vox-core/src/node/paths.rs:28:    pub config_dir: PathBuf,
crates/vox-core/src/node/paths.rs:55:        let config_dir = match config_override {
crates/vox-core/src/node/paths.rs:65:        create_private_dir(&config_dir)?;
crates/vox-core/src/node/paths.rs:67:            config_dir,
---
crates/vox-tui/src/tunnel_cli.rs:87:    anchors: vox_core::nat::bootstrap::BootstrapSet,
crates/vox-tui/src/tunnel_cli.rs:91:    let cfg = NodeConfig::new().bind(Bind::Addr(listen)).anchors(anchors);
crates/vox-tui/src/tunnel_cli.rs:112:    anchors: vox_core::nat::bootstrap::BootstrapSet,
crates/vox-tui/src/tunnel_cli.rs:117:    let cfg = NodeConfig::new().bind(Bind::Addr(listen)).anchors(anchors);
crates/vox-tui/src/tunnel_cli.rs:311:fn reachable_or_relayed(node: &NodeHandle, anchors: &BootstrapSet) -> bool {
crates/vox-tui/src/tunnel_cli.rs:312:    if !anchors.nodes().is_empty() {
crates/vox-tui/src/tunnel_cli.rs:330:    anchors: &BootstrapSet,
crates/vox-tui/src/tunnel_cli.rs:335:    if !reachable_or_relayed(node, anchors) {
crates/vox-tui/src/tunnel_cli.rs:497:    /// The anchors to reach the swarm through.
crates/vox-tui/src/tunnel_cli.rs:498:    pub anchors: vox_core::nat::bootstrap::BootstrapSet,
[0m
[0m→ [0mRead crates/vox-core/src/governance/vectors.rs[90m [offset=900, limit=240][0m
I need to pin down one crucial evaluator behavior: what happens to consent edges, certificates, and exclusions across an epoch bump. Let me look at the golden vectors.
[0m
[0m$ [0mgrep -n 'epoch' crates/vox-core/src/governance/vectors.rs | grep -in 'rotat\|exclusion\|finding\|resurrect\|clear' ; echo "---"; grep -n 'fn vector.*epoch\|rotation' crates/vox-core/src/governance/vectors.rs | head -20
13:276:            let x = ServiceGrantExclusion::build(issuer, channel_id, epoch, target).unwrap();
24:387:        /// Append a passphrase-rotation (epoch bump) from `issuer`.
27:395:            let r = PassphraseRotation::build(issuer, channel_id, old_epoch, new_epoch).unwrap();
32:1609:    fn adversarial_passphrase_rotation_tracks_epoch_and_is_total() {
33:1610:        // An authorized passphrase-rotation bumps the channel epoch; resolution is
35:1617:        // creator (admin → holds passphrase-rotate) bumps epoch 0 → 1.
40:1635:        // No passphrase-rotation has run, so max established epoch is 0. A cert at
42:1657:        // A non-admin's passphrase-rotation does not bump the epoch.
43:1672:        // Outsider has no passphrase-rotate authority → epoch stays 0.
45:1677:    fn adversarial_rotation_with_wrong_old_epoch_ignored() {
46:1678:        // An authorized rotation whose old_epoch does not chain off the current
49:1689:        // The rotation does not chain off epoch 0 → ignored → epoch stays 0.
51:1694:    fn adversarial_unauthorized_rotation_does_not_let_future_epoch_entries_through() {
52:1695:        // An UNAUTHORIZED rotation must NOT establish a new epoch, so a governance
55:1707:        // established (the rotation was unauthorized), so this cert is future-epoch
58:1813:    fn adversarial_future_epoch_cert_cannot_bootstrap_its_own_rotation() {
59:1814:        // Future-epoch bootstrap rejected: a rotation to epoch 1 must be authorized
61:1816:        // epoch 1 — which only the rotation itself would establish — is NOT in-effect
62:1824:        // creator grants K `passphrase-rotate` but BOUND TO EPOCH 1 (a future epoch
65:1837:        // K is not authorized → the rotation does not establish epoch 1.
67:1850:            "a future-epoch cert must not bootstrap the rotation that establishes its epoch"
---
25:    use crate::governance::rotation::PassphraseRotation;
387:        /// Append a passphrase-rotation (epoch bump) from `issuer`.
388:        pub fn passphrase_rotation(
1609:    fn adversarial_passphrase_rotation_tracks_epoch_and_is_total() {
1610:        // An authorized passphrase-rotation bumps the channel epoch; resolution is
1618:        h.passphrase_rotation(&creator, &cid, 0, 1);
1635:        // No passphrase-rotation has run, so max established epoch is 0. A cert at
1656:    fn adversarial_unauthorized_passphrase_rotation_ignored() {
1657:        // A non-admin's passphrase-rotation does not bump the epoch.
1664:        h.passphrase_rotation(&outsider, &cid, 0, 1);
1677:    fn adversarial_rotation_with_wrong_old_epoch_ignored() {
1678:        // An authorized rotation whose old_epoch does not chain off the current
1686:        h.passphrase_rotation(&creator, &cid, 5, 6);
1689:        // The rotation does not chain off epoch 0 → ignored → epoch stays 0.
1694:    fn adversarial_unauthorized_rotation_does_not_let_future_epoch_entries_through() {
1695:        // An UNAUTHORIZED rotation must NOT establish a new epoch, so a governance
1704:        // Outsider (no authority) forges a rotation 0→1.
1705:        h.passphrase_rotation(&outsider, &cid, 0, 1);
1707:        // established (the rotation was unauthorized), so this cert is future-epoch
1813:    fn adversarial_future_epoch_cert_cannot_bootstrap_its_own_rotation() {
[0m
[0m→ [0mRead crates/vox-core/src/governance/vectors.rs[90m [offset=1605, limit=60][0m
[0m
[0m$ [0mgrep -n 'epoch' crates/vox-core/src/node/channel.rs | grep -v '^.*//' | head -60
142:    epoch: u64,
147:        epoch,
164:        crate::wire::WireError::EpochMismatch => "sync failed: epoch mismatch",
247:    epoch: u64,
304:            .field("epoch", &self.epoch)
314:fn manifest_bytes(genesis: &Genesis, local_name: &str, created: u64, epoch: u64) -> Vec<u8> {
321:        .uint(epoch);
340:    let epoch = d.uint()?;
342:    Ok((genesis, name, created, epoch))
369:    epoch: u64,
380:        epoch,
668:        let epoch = 0u64;
674:        let sender = SenderChain::new(&channel_id, epoch, &me, 0, now_secs)?;
679:        retain_generation(&mut origins, &channel_id, epoch, &me, &sender, now_secs)?;
681:        let manifest = manifest_bytes(&genesis, local_name, now_secs, epoch);
733:        admission.admit(channel_id, epoch, me);
741:            epoch,
782:        let (genesis, local_name, created, epoch) = parse_manifest(&manifest)?;
806:            admission.admit(*channel_id, epoch, *author);
916:            epoch,
1012:        let epoch = 0u64;
1016:        let sender = SenderChain::new(channel_id, epoch, &me, 0, now_secs)?;
1018:        retain_generation(&mut origins, channel_id, epoch, &me, &sender, now_secs)?;
1025:        let manifest = manifest_bytes(genesis, local_name, now_secs, epoch);
1075:            admission.admit(*channel_id, epoch, *author);
1084:            epoch,
1134:            .admit(self.channel_id, self.epoch, fingerprint);
1322:            self.epoch,
1377:            self.epoch,
1436:        if self.origins.has(&self.channel_id, self.epoch, chain_id) {
1438:                .release_at(signer, &self.channel_id, self.epoch, chain_id, 0)
1513:            issue_consent_revocation(signer, &self.channel_id, self.epoch, target, new_chain_id)?;
1569:            self.epoch,
1610:        let exclusion = ServiceGrantExclusion::build(signer, &self.channel_id, self.epoch, member)?;
1856:        let chain = ReceiverChain::from_skdm(skdm, &key, &self.channel_id, self.epoch)?;
2025:        if entry.skeleton.epoch != self.epoch {
2026:            return Err(Error::MalformedGovernance("entry binds another epoch"));
2211:            epoch: self.epoch,
2239:    pub fn epoch(&self) -> u64 {
2240:        self.epoch
2315:        join_context_from_genesis(&self.genesis, self.epoch)
[0m
I need to understand exactly how finding #5 manifests mechanically. Let me check how the channel handles an epoch change and whether exclusions/consent persist across it.
[0m$ [0mgrep -n 'exclusion\|excluded' crates/vox-core/src/governance/vectors.rs | head -30; echo "---"; sed -n '1140,1260p' crates/vox-core/src/governance/vectors.rs
268:        /// Append a service-grant exclusion from `issuer` against `target` (ADR-017).
269:        pub fn service_grant_exclusion(
1024:    /// An authorized exclusion withdraws the grant from one member and leaves the
1027:    fn vector_service_grant_exclusion_removes_one_member_only() {
1036:        h.service_grant_exclusion(&creator, &cid, 0, out.fingerprint());
1055:        assert!(eval.is_excluded(&out.fingerprint()));
1062:    /// An exclusion from an identity that holds no `delegate` is inert — the same
1065:    fn vector_unauthorized_service_grant_exclusion_ignored() {
1074:        h.service_grant_exclusion(&nobody, &cid, 0, target.fingerprint());
1086:        assert!(!eval.is_excluded(&target.fingerprint()));
1093:    /// An exclusion suppresses the *grant*, never a certificate. An admin who excludes
1096:    fn vector_an_explicit_cert_survives_a_service_grant_exclusion() {
1104:        h.service_grant_exclusion(&creator, &cid, 0, member.fingerprint());
1127:            "the certificate is governed by its own revocation, not by the exclusion"
---
            min_suite: crate::suite::SuiteFloor::DAY_ONE.id(),
        };
        for cap in [
            Capability::Admin,
            Capability::Delegate,
            Capability::Policy,
            Capability::PassphraseRotate,
            Capability::Invite,
            Capability::role("ops"),
        ] {
            let grant = CapabilitySet::from_iter_caps([cap.clone()]);
            assert!(
                Genesis::create_with_nonce_and_grant(&creator, 1_000, policy, grant, [0x5A; 16])
                    .is_err(),
                "a genesis must not confer {cap:?} on every member"
            );
        }
    }

    // ---- Policy vectors. ----

    #[test]
    fn vector_policy_update_changes_history_and_ttl_not_deniability() {
        let creator = root(1, 1);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();
        assert_eq!(genesis.body.policy.history_mode, HistoryMode::ForwardOnly);
        assert_eq!(
            genesis.body.policy.deniability_mode,
            DeniabilityMode::Attributable
        );

        let mut h = LogBuilder::new(&genesis);
        // Creator (admin → holds policy) updates history+ttl.
        h.policy_update(
            &creator,
            &cid,
            0,
            Some(HistoryMode::FullHistory),
            Some(3600),
        );

        let eval =
            Evaluator::build(&genesis, &h.entries(), 2_000, key_resolver(vec![&creator])).unwrap();
        let p = eval.policy();
        assert_eq!(p.history_mode, HistoryMode::FullHistory);
        assert_eq!(p.ttl, 3600);
        // Deniability is genesis-immutable, unchanged.
        assert_eq!(p.deniability_mode, DeniabilityMode::Attributable);
    }

    #[test]
    fn vector_suite_floor_raise_applies_lower_ignored() {
        // ADR-003: "the floor advances deliberately and never silently
        // downgrades" — a policy-holder can RAISE min_suite; an update naming a
        // suite ranked below the floor in force is ignored (its other fields
        // still apply). The registry's test-only rank-0 suite is the weaker one.
        use crate::suite::{SuiteFloor, VOX_SUITE_1, VOX_SUITE_TEST_WEAK};
        let creator = root(1, 1);

        // Channel created at the weak floor; the creator raises it to suite-1.
        let policy = ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
            min_suite: VOX_SUITE_TEST_WEAK.id,
        };
        let genesis = Genesis::create_with_nonce(&creator, 1_000, policy, [0x5B; 16]).unwrap();
        let cid = genesis.channel_id();
        let mut h = LogBuilder::new(&genesis);
        h.policy_update_min_suite(&creator, &cid, 0, None, VOX_SUITE_1.id);
        let eval =
            Evaluator::build(&genesis, &h.entries(), 2_000, key_resolver(vec![&creator])).unwrap();
        assert_eq!(eval.policy().min_suite, VOX_SUITE_1.id);
        assert_eq!(eval.policy().suite_floor().unwrap(), SuiteFloor::DAY_ONE);

        // Channel created at suite-1; an authorized update naming the weak suite
        // is ignored for the floor (but its ttl still applies).
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();
        let mut h = LogBuilder::new(&genesis);
        h.policy_update_min_suite(&creator, &cid, 0, Some(77), VOX_SUITE_TEST_WEAK.id);
        let eval =
            Evaluator::build(&genesis, &h.entries(), 2_000, key_resolver(vec![&creator])).unwrap();
        assert_eq!(
            eval.policy().min_suite,
            VOX_SUITE_1.id,
            "floor must not lower"
        );
        assert_eq!(
            eval.policy().ttl,
            77,
            "other fields of the same update apply"
        );
    }

    #[test]
    fn vector_unauthorized_policy_update_ignored() {
        // A non-admin authoring a policy-update has no effect (no policy cap).
        let creator = root(1, 1);
        let outsider = root(9, 9);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        h.policy_update(&outsider, &cid, 0, Some(HistoryMode::FullHistory), None);

        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &outsider]),
        )
        .unwrap();
        // Genesis policy unchanged: the outsider's update is ignored.
        assert_eq!(eval.policy().history_mode, HistoryMode::ForwardOnly);
    }

    // ---- Cross-channel + forgery rejection. ----

    #[test]
[0m
[0m→ [0mRead crates/vox-core/src/node/channel.rs[90m [offset=1995, limit=80][0m
[0m
[0m$ [0mgrep -m2 'version' Cargo.toml; echo "---"; sed -n '300,420p' crates/vox-tui/src/tunnel_cli.rs
version = "0.1.0"
rust-version = "1.94"
---
    let _ = node.apply(NodeCommand::StopForward { local: bound }).await;
    let _ = node.apply(NodeCommand::Shutdown).await;
    Ok(())
}

/// Whether this node could be reached by someone who was handed its address — a
/// routable advertised endpoint, or an anchor that will relay for it.
///
/// `vox serve` refuses to start when neither holds (ADR-017 decision 4): minting an
/// address nobody can use is worse than saying so, because the host would hand it out
/// and only learn later.
fn reachable_or_relayed(node: &NodeHandle, anchors: &BootstrapSet) -> bool {
    if !anchors.nodes().is_empty() {
        return true;
    }
    node.view().listening.iter().any(|text| {
        Multiaddr::parse(text)
            .ok()
            .and_then(|m| m.socket_addr())
            .is_some_and(|sa: SocketAddr| is_routable(&sa.ip()))
    })
}

/// `vox serve <port>` — create a service room, offer the port in it, and serve until
/// interrupted (ADR-017 decisions 3 and 4).
///
/// Prints three things and says plainly that two of them must travel separately: the
/// address is a rendezvous, and the passphrase is what turns it into access (ADR-005).
pub async fn serve(
    node: &NodeHandle,
    anchors: &BootstrapSet,
    name: &str,
    port: u16,
    at: Option<SocketAddr>,
) -> Result<(), AppError> {
    if !reachable_or_relayed(node, anchors) {
        return Err(AppError::Usage(
            "this machine has no address a guest could reach and no anchor to relay \
             through.\n       Run `vox node` somewhere reachable and pass its \
             `<fingerprint>@<multiaddr>` here as --anchor,\n       or open a port on \
             your router. Refusing to mint an address nobody can use."
                .into(),
        ));
    }
    let passphrase = vox_core::node::passphrase::generate(PASSPHRASE_GROUPS)?;
    let before: Vec<Digest32> = node.view().channels.iter().map(|c| c.channel_id).collect();
    let out = node
        .apply(NodeCommand::Serve {
            local_name: name.to_owned(),
            passphrase: Secret::new(passphrase.as_bytes().to_vec()),
            port,
            at,
        })
        .await;
    if !out.is_done() {
        return Err(AppError::Usage(format!(
            "cannot serve port {port}: {out:?}"
        )));
    }
    let channel_id = node
        .view()
        .channels
        .iter()
        .map(|c| c.channel_id)
        .find(|id| !before.contains(id))
        .ok_or_else(|| AppError::Usage("the room was not created".into()))?;

    let out = node.apply(NodeCommand::Invite { channel_id }).await;
    if !out.is_done() {
        return Err(AppError::Usage(format!("cannot mint an address: {out:?}")));
    }
    let url = loop {
        match node.next_event().await {
            Some(NodeEvent::InviteLink { url, .. }) => break url,
            Some(_) => {}
            None => return Err(AppError::Usage("the node stopped".into())),
        }
    };

    let endpoint = at.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], port)));
    println!("room       {}", b32_encode(&channel_id));
    println!("address    {url}");
    println!("passphrase {}", passphrase.as_str());
    println!("           ^ send this by a different channel than the address");
    println!();
    println!("serving {endpoint}. anyone who joins with both may reach it, at");
    println!("port {port} of {}", vox_hostname(&channel_id));
    println!("Ctrl-C to stop");

    // Until interrupted: report who reaches the service. The service itself cannot say
    // — every Vox client arrives at it from loopback (ADR-017 decision 6).
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            event = node.next_event() => match event {
                Some(NodeEvent::TunnelServed { client, service_tag, .. }) => {
                    println!("vox: {} reached {service_tag:?}", short(&client));
                }
                Some(NodeEvent::PeerJoined { peer, .. }) => {
                    println!("vox: {} joined", short(&peer));
                }
                Some(_) => {}
                None => return Err(AppError::Usage("the node stopped".into())),
            },
        }
    }
    println!("vox: stopping");
    let _ = node.apply(NodeCommand::Shutdown).await;
    Ok(())
}

/// `vox connect <address>` — join the room an address names, and print the name its
/// services answer on (ADR-017 decision 4).
///
/// One-shot: joining is a durable act recorded in the profile, so there is nothing to
/// keep running. What makes the printed name resolve is `vox up` (decision 5).
pub async fn connect(
    node: &NodeHandle,
    url: &str,
    name: &str,
    room_passphrase: &str,
[0m
One more verification — the version claim and whether `vox serve`'s current output reports any audience info.
[0m$ [0mgrep -n 'fn classify_payload' -A 40 crates/vox-core/src/node/channel.rs | head -60
546:pub(crate) fn classify_payload(payload: &[u8]) -> Result<EntryKind> {
547-    if payload.starts_with(GROUP_MSG_SIGN_DOMAIN.as_bytes()) {
548-        return Ok(EntryKind::Content);
549-    }
550-    if crate::wire::parse_frame(payload).is_ok() {
551-        return Ok(EntryKind::Governance);
552-    }
553-    Err(Error::MalformedAtRest(
554-        "entry payload is neither a group message nor a governance struct",
555-    ))
556-}
557-
558-fn cache_bytes(r: &Rendered) -> Vec<u8> {
559-    let mut e = Encoder::new();
560-    e.array(5)
561-        .uint(CACHE_VERSION)
562-        .bytes(&r.entry_hash)
563-        .bytes(&r.author)
564-        .uint(r.created_secs)
565-        .text(&r.text);
566-    e.finish()
567-}
568-
569-fn parse_cache(bytes: &[u8]) -> Result<Rendered> {
570-    let mut d = Decoder::new(bytes);
571-    if d.array()? != 5 {
572-        return Err(Error::MalformedAtRest("plaintext cache arity"));
573-    }
574-    if d.uint()? != CACHE_VERSION {
575-        return Err(Error::MalformedAtRest("plaintext cache version"));
576-    }
577-    let entry_hash: Digest32 = d
578-        .bytes()?
579-        .try_into()
580-        .map_err(|_| Error::MalformedAtRest("plaintext cache entry hash"))?;
581-    let author: Digest32 = d
582-        .bytes()?
583-        .try_into()
584-        .map_err(|_| Error::MalformedAtRest("plaintext cache author"))?;
585-    let created_secs = d.uint()?;
586-    let text = d.text()?.to_owned();
[0m
I have read the three ADRs, the governed code, the gates, and the cited Tor source. Findings below, in the order posed.

---

## 1. Is "reach == the host's approved-reader set" sound, or does it move the vulnerability?

**The core mechanism is sound; the plan is right about the parts it verified and silent about the parts it didn't.** What I verified in the code:

- **The consent set is single-writer, locally authored, and cannot be influenced by a peer.** Consent entries are signature-verified per author (`evaluator.rs:239-241`, `verify_body` → `ConsentGrant::verify`), and `resolve_consent` (evaluator.rs:757-782) only folds edges authored by `A` about `A`. The host's own grants/revocations are appended locally first (`channel.rs:1635-1688`, evaluator rebuilt at :1681), so the host's dial gate is always current w.r.t. its own acts. A peer's only lever is withholding sync — which fails *closed* (a reader whose grant hasn't synced can't reach; a revocation the host authored is in effect at the host immediately). No forgery path exists.
- **The vouching interaction is as the plan says.** `learn_members` (actor.rs:2085-2119) admits authors from a peer's board on `MemberBundleRecord::verify`, which is a self-signature check (nat/record.rs:629-642) — that's the bug, correctly named. Under the withdrawn model it escalated because `build_evaluator` fed `authors.keys()` into the genesis grant (channel.rs:946-952). Under the new model admission feeds nothing: the dial gate is `readers_of(host)`, which a self-signed admission never touches. "Non-escalating" is accurate — for the service path. (The bug still admits a stranger's entries into your DAG and mirrors them to anchors — spam/DoS surface, so M17.6 is still owed, as the plan says.)

**Where the model genuinely re-scopes rather than removes risk — and the plan doesn't say so:**

- **The reused decision was made about messages, in a UI that still says so.** The strongest attack is not cryptographic: it is temporal. A host approves a reader in a chat room for chat reasons; months later runs the ADR's own example, `vox serve a3f9c2 22` (decision 4 serves SSH into a room called *design-review*). Decision 3 states proudly: "in that moment, [the host] has given all five reach." The only disclosure the plan mandates is a *count* at serve time (decision 4, "serving … to 3 of 5 members"). The consent-grant verb — the moment the decision is actually made — says nothing about services (vox-tui live.rs:336-345 sends `NodeCommand::Consent` with no service disclosure; ui.rs:46 shows "↔ consented"). The plan's own rules list (decision 4) requires audience reporting from `vox serve` but requires nothing from the consent surface. If the model's entire justification is "the human decision already happened," then the surface where it happens must say what it now means, and the serve-time report must name identities, not counts. As written, neither is specified.
- **The union rule cuts both ways.** Decision 3: a service bound to two rooms is reachable by the union. Revoking a reader *in one room* (the TUI revoke is per-room, `RevokeConsent { channel_id, member }`) does not cut their reach if they're approved in the other. A host who thinks "I revoked Mallory in design-review" has not revoked Mallory's path to the service also bound to ops-room. The plan states the union rule and never discusses the revocation-side confusion.
- **The plan's claim "non-escalating" for vouching is correct, but note the asymmetry it introduces:** a malicious member can unilaterally advertise *to* anyone it approves (the audience is the host's own consent set, host-controlled). That's inherent to host-initiated approval and fine — but it's worth one sentence, since the reader's consent to the host is not required for the host to make a service known and reachable to them.

Verdict on the question: the vulnerability is removed, not moved — with the caveat that what replaces it is a human decision made in the wrong context, and the plan's disclosure requirements don't cover that context.

## 2. Decision 9's "no party holds the descriptor, lacks approval, and knows the name"

**False as written, twice over — and the conclusion survives for reasons the plan didn't state.**

- **The anchor is exactly the party the plan's premise denies.** Decision 9 says: "Vox's carrier is the room's own log, which only members sync." That is factually wrong in this tree. An anchor is a *non-member* that syncs and durably stores the full log: anchor.rs:4-9 ("A node that anchors a room it is not a member of holds, for that room, … the log's entries") and actor.rs:2054-2063 ("An anchor reconciles every channel it keeps with each of that channel's known members"). So a non-member holds the descriptor and lacks approval. What saves the construction is that the name is *inside* the reader-sealed envelope — the anchor learns existence, size (audience count), and update cadence, never the name. The plan's stated reason ("only members sync") is wrong; the load-bearing reason (name inside the seal) is present in the text but is not what the sentence says. Given the deployment shape ADR-012 assumes — the anchor is *the host's own* always-on node — the metadata exposure is to the host's own infrastructure, which is acceptable, but the ADR must say the true thing: the descriptor is held by non-members by design.
- **A revoked reader is precisely "holds the descriptor, lacks approval, knows the name."** Log records are durable (the plan admits this: "a revoked reader keeps the last descriptor it could open"). They opened it before revocation, so they hold it, lack approval, and know the name — and also the ports and the host's overlay address. So the named party *exists*. The reason one layer nonetheless suffices is not that the party doesn't exist; it's that Tor's inner layer compensates for the *absence of a dial-time gate* (introduction points accept circuits from whoever can decrypt), while Vox has the gate: `session::accept` enforces the consent check before any local connect (session.rs:251-255), and decision 10.4 refuses cached-descriptor dials. The correct sentence is "such a party exists and can do nothing with what it holds, because authorization is re-checked at dial time." This matters because the plan derives "no second layer to add" from a false invariant; the true invariant is what M17.10/M17.11 must be gated against.

Tor citations check out, for the record: `hs_common.c:897-906` builds `base32(PUBKEY ‖ CHECKSUM ‖ VERSION)`; `hs_descriptor.c:9-52` documents the two layers exactly as the plan's table says (outer keyed off the blinded pubkey "to protect against entities who don't know its onion address"); the auth-client emission is at ~:700-720 and the cookie KDF `KDF(subcredential ‖ x25519(service_sk, client_pk))` at ~:1424-1440.

## 3. Decision 9's freshness keying: `chain_id` vs epoch

**The central claim is correct and verified.** ADR-007:186-204: revocation advances *"`A`'s own `chain_id` … **not** the channel `epoch`*. Code: `revoke_consent` rotates first (`channel.rs:1510` → `rotate_sender` advances the chain) and records `new_chain_id`. The evaluator advances `current_epoch` only on authorized `PassphraseRotation` entries (evaluator.rs:533-558). The plan's self-correction narrative ("taken on a wrong premise … epoch advances only on a passphrase rotation") is accurate. The epoch is genuinely the wrong counter for revocation.

**But the freshness mechanism as specified has two holes:**

- **Consent *grants* don't advance `chain_id`.** `issue_consent` (channel.rs:1311-1333) appends the grant and delivers the *current* SKDM — no rotation. So the specified republication trigger ("republished when that generation advances") never fires on the event that *adds* a reader. A host that approves a new reader after publishing its descriptor leaves that reader with no wrapper until the next rotation. Scheduled rotation won't save them: `should_rotate_sender` is consulted only in the send path (actor.rs:2895-2896) — a host that serves but never *speaks* in the room never rotates on schedule. Decision 3's "approving a reader takes effect immediately and needs no second act" is true at the dial gate and **false for discovery** as decision 9 is written. The fix is one line of spec (re-seal on every consent-set change, grant included); the plan doesn't contain it.
- **Decision 10.3 contradicts decision 9 in the same document.** Decision 10 says the descriptor is republished "on the epoch bump" (ADR-017:470) — the very premise decision 9 records as corrected (ADR-017:426-443). Since revocation does not bump the epoch, an implementer following decision 10.3 would never republish on revocation. Leftover pre-correction text; must be struck.

Two smaller notes: `chain_id` also advances on scheduled rotation (ADR-006: N=1000 messages / T=7 days), so the descriptor would churn on the log with no audience change — harmless but worth stating, since the cadence is visible to every log holder, anchors included. And "the sealing work is the SKDM distribution that already happens" conflates substrates: SKDMs travel over pairwise sessions and *never touch the log* (consent.rs: "the SKDM travels in the pairwise session, not inline"; skdm.rs:20-26), while the descriptor is a log-resident artifact. M17.10 is new wire mechanism, not reuse — which also contradicts the context section's "without adding any mechanism at all."

## 4. Decision 1's per-service keypair: is the attack real, and is the keypair necessary?

**The attack is real; the keypair stops it; the justification is incomplete.** In the label model, the name is the service's only cross-room identity ("The name is the service"), so an approved reader re-publishing name N in a second room with itself as host creates a genuine ambiguity that no signature by the *host's member key* resolves — the republisher signs as itself and the label binds to nothing. A descriptor signed by the service key makes the forgery impossible. Sound.

But the plan's rejected-alternative analysis never considers the cheaper construction that also stops it: **name = base32(H(host_pubkey ‖ 256-bit label))**. That name is unguessable (the rejected "room + host + port" derivation was rejected for guessability — correctly, port space is 16 bits — but a random label is not guessable) *and* host-committed: a reader republishing N in another room fails every client's check that the descriptor's signer matches the key the name commits to. No new key material, no "lost key = lost name" (which the plan carries as a Negative). The keypair's actual distinguishing advantage — the name survives the host's identity rotation, and the service key can be moved to another machine — is real but never stated. The decision should be justified against the host-committed label, not against the strawman it defeated. Non-blocking: the chosen construction is sound; the reasoning is incomplete.

Related and unspecified: **when does `vox serve` reuse a key versus mint one?** Decision 3 says "the name is stable across [rooms]" and decision 4 says "one name, many ports" — implementable only if the client persists a (host, room-set/endpoint) → key mapping and reuses it. The plan says the key is "persisted in the profile directory" and nothing about the reuse key. And the stable name is a cross-room correlation handle: any party holding descriptors from two rooms for the same service key can equate the hosts. Unmentioned.

## 5. "A `.vox` name is not a bearer capability"

**True under the plan as written, including the other-room case.** The name confers nothing because (a) it does not even resolve without an openable descriptor (M17.9's gate: "a name for a service this client holds no openable descriptor for does not resolve at all"), and (b) the dial is re-gated by the host's consent check regardless of cached reach information (session.rs:251-260 today; decision 10.4 explicitly). Someone approved in another room with the same host either has the service bound there too (legitimate union reach — the name added nothing) or doesn't (resolve fails uniformly, up.rs:128-133). A name pasted to an unapproved member of the same room plus the room's log gives them a sealed envelope they cannot open and a string that resolves nowhere. The claim holds. One caveat worth recording: the safety of the name is *load-bearing on M17.9/M17.10 actually shipping* — until then, the shipped name is the channelID (resolver.rs), which is the room's join identifier, and that string is very much not paste-safe.

## 6. Does the plan's account of what ships match the tree?

- **"v0.1.0 implements the withdrawn model": TRUE.** `GenesisBody::service_grant` ships (genesis.rs:232, 387), `servicegrant.rs` (0x0013) ships, `build_evaluator` feeds `authors.keys()` (channel.rs:946-952), `vox serve` mints a grant room (actor.rs:2570-2613), `vox grant` ships (cli.rs:397-399 → actor.rs:2713), and the current `vox serve` output tells the host "anyone who joins with both may reach it" (tunnel_cli.rs:~380). `node_m17_serve_gate.rs` asserts the negative "nowhere does this test issue GrantTunnel." The plan's characterization is accurate.
- **"The M17.3 gate asserts the vulnerability": TRUE.** node_m17_up_gate.rs:116-143 builds the evaluator over the genesis grant with the guest as a bare member, no certificate; the echo round-trips (:226-229). The plan's quoted characterization is exact.
- **"Decisions 5, 6 and 7 are built and shipped": decision 7 is NOT.** There is no `<config_dir>/anchors` anywhere in the tree. `Paths` knows only `vault.cbor` and `store.redb` (paths.rs:18-21); `vox node` *prints* anchor specs to stdout on a tick (app.rs:291-297) and every client command still takes `--anchor`/`VOX_ANCHORS` per invocation (cli.rs:45-49). The header's parenthetical "(`node::up`, `node::resolver`, `<config_dir>/anchors`)" overclaims: the first two exist, the third does not. The "six steps" critique's step 2 is still exactly as built.
- **ADR-013's in-place amendments describe code that doesn't exist.** ADR-013:240-243 says the m15 gate was "Rewritten 2026-09-21 … the transition is now a single human act" — but `node_m15_anchor_gate.rs:660-670` still drives `NodeCommand::GrantTunnel` ("Alice grants Bob dial:ssh"). The commit message itself says the gate "must be rewritten" (future tense); the ADR body says it was. ADR-013:233-235 says "`vox grant` is withdrawn … there is nothing left for it to grant" — cli.rs:397-399 and actor.rs:2713 ship it. ADR-017's own header is careful ("proposed and not built"); ADR-013's amendments are not. In a document whose authority rests on having caught two prior wrong revisions, present-tense falsehoods about the tree are exactly the failure mode to eliminate.

## 7. What is missing entirely

1. **Bind authorization has no story.** `add_service` requires `bind:<tag>` in the channel evaluator (channel.rs:1232). With the genesis grant withdrawn and `vox grant` deleted, the only remaining bind holder is the room creator (admin implies all). Decision 4's central case — "a chat room, an agent room, *any room the host is in*" — is unreachable for a non-creator host. M17.7 never says what replaces the bind check. Either bind becomes self-authorized (any member may serve *its own* consent set — coherent with the model, but then any member can spam descriptors onto the room's log, bounded per host by MAX_SERVICES but not per room) or it stays admin-gated (requires the verb the plan deleted). The plan must choose; as written M17.7 is not implementable beyond creator-hosts. **This is the plan's largest hole.**
2. **The room loses all power over a bound service, and the plan never says so.** The withdrawn model gave the room two levers (0x0013 exclusion by `delegate` holders, cert revocation by the issuer). Under the new model the *only* party who can cut a reader's reach to host H's service is H. If the room shuns the host (every member revokes consent *to* it — ADR-007's only per-member removal), the host's *outbound* consent set — its service audience — is untouched, and it keeps serving. Nothing in the plan addresses whether a service bound to a room should outlive the host's standing in it. A passphrase rotation does kill it (see below), but that evicts everyone.
3. **Epoch transitions are undiscussed, and they are load-bearing for services.** The channel layer rejects entries bound to another epoch (channel.rs:2025-2026) and `ChannelState.epoch` never advances in place (set at create/join/open: :668, :741, :916, :1012; no setter). A passphrase rotation therefore wipes *all* consent edges, certs, and exclusions at the channel layer — "the room starts again from its genesis" is literal. Consequences the plan owes and doesn't have: (a) eviction of a *reader* via rotation works for services only because consent doesn't cross epochs — worth stating, since decision 9's freshness analysis never touches it; (b) every routine rotation wipes every service audience and every descriptor (SKDM sealing is `(channelID, epoch)`-bound, skdm.rs:28-32) — the host must re-consent and republish from scratch; (c) a host rotated *out* keeps its epoch-0 state and its epoch-0 evaluator, and would still grant a dial from a stale epoch-0 client — clients that rejoined can't open old descriptors, which is the practical cut-off, but the gate itself doesn't know the room moved on.
4. **M17.10's kind-hiding gate contradicts its stated vehicle.** The gate requires an unapproved member to be unable to determine "that it is a service descriptor rather than any other sealed entry." But M17.5 says "0x000F advertisements become the descriptor," and the log classifier (channel.rs:546-556) accepts exactly two payload shapes: group-message domain (Content) or a parseable wire frame (Governance) — a framed `0x000F` is visible to every log holder, anchor included, and an *opaque* payload is rejected outright ("entry payload is neither a group message nor a governance struct"). So the property needs either a new opaque entry kind (new mechanism the plan disclaims) or descriptor-as-content from the host — which, note, would inherit exactly the right audience (the host's sender key seals to exactly `readers_of(host)`), hide the kind perfectly among chat ciphertext, and ride `chain_id` for free. The plan's per-reader wrapper construction buys nothing over that under a one-axis model (there is no "approved for messages but not for this service" state to express) — at minimum the choice must be made with the alternative named.
5. **A host that "leaves" is undefined.** Closing the channel locally drops it from `host_snapshot` (actor.rs:2856-2872) so dials fail uniformly — fine — but the descriptor persists on the durable log and readers keep resolving a name that will always refuse. No tombstone/delist. Minor hygiene gap.
6. **Two hosts, same port, one room: actually handled.** Per-service names disambiguate what channelID-naming couldn't; the dial targets a specific host connection and each host resolves its own services map (node/tunnel.rs:89-100). This one the plan gets right — say so.
7. **`vox up`'s shape changes and "stands as built" hides it.** As built, `vox up` is per-room (cli.rs:333-341, `UpArgs` carries `RoomArgs`) and resolves channelID-names of grant rooms (resolver.rs:86-99). The plan's own table sells "`vox up`, plus a `ProxyCommand` for `*.vox` … written once for every room there will ever be" — i.e., room-global resolution from all openable descriptors. M17.9 admits the resolver rewrite but the "decisions 5/6/7 are unaffected and stand as built" claim (header, :17-18) papers over a CLI-breaking change. `vox forward`'s role stays coherent (per-host dial, consent gate; the no-proxy fallback).

## 8. Deleting `vox grant`

The plan's stated losses are real but its list is incomplete, and one claim is wrong:

- **Wrong:** "Reach … could be extended to a non-member" with `vox grant`. It could not, even today: `grant_tunnel` requires the target to be an admitted author of the room (actor.rs:2735-2743). What it *could* do is grant an admitted-but-never-consented author — reach without read — which is the loss the plan should have named.
- **Unconsidered use 1: bind delegation** — see 7.1; deleting the verb before answering "who may bind" breaks the plan's own central flow.
- **Unconsidered use 2: time-bounded reach.** `vox grant --days` (cli.rs:289-291 → cert expiry in `grant_capabilities`, channel.rs:1554-1576) is the only time-limited authorization in the system. Consent has no expiry. "Contractor gets SSH for a week" becomes "remember to revoke, which also revokes their read access." The give-up list (decision 3) names narrowing and non-member reach but not this.
- The narrowing answer ("use a second room") is a coherent design position and I won't relitigate it — but note it reintroduces exactly the join step the plan eliminated, for exactly the users who needed selectivity.

## VERDICT

**REVISE** — the core decision (consent as the sole authorization surface, per-service keypair, client-authorized descriptor, `chain_id` freshness) is sound and verified against the tree, but the plan is not implementable as written and misstates both itself and the code in load-bearing places. In priority order:

1. **Specify bind authorization under the new model** (currently unspecified; with the genesis grant and `vox grant` gone, a non-creator host cannot pass `channel.rs:1232`, contradicting decision 4's "any room the host is in"). M17.7 cannot land without this.
2. **Fix decision 9's republication triggers**: re-seal on consent *grants*, not only `chain_id` advances (scheduled rotation fires only on send, actor.rs:2895-2896 — a quiet host's late-approved reader may never discover the service, falsifying decision 3's "immediately"); and strike decision 10.3's "on the epoch bump," which contradicts decision 9's own correction.
3. **Specify host-removal and epoch semantics**: state that only the host can cut a reader's reach (the room's levers are gone — decide whether that's intended and say it plainly), and state what a passphrase rotation does to services, audiences, and descriptors (total wipe at the channel layer, channel.rs:2025-2026; re-consent and republish required).
4. **Correct decision 9's false premises and reconcile it with the carrier**: anchors are non-member log holders (anchor.rs:4-9, actor.rs:2054-2063), so "only members sync" is false; "no party holds+lacks-approval+knows-the-name" is false (every revoked reader is one) — the correct justification is the dial-time gate plus name-inside-the-seal. Then reconcile M17.10's kind-hiding gate with the fact that a framed `0x000F` is visible to all log holders and an opaque payload is rejected by the classifier (channel.rs:546-556); evaluate descriptor-as-content, which inherits the right audience, hiding, and freshness for free.
5. **Fix the false claims about the tree**: decision 7's `<config_dir>/anchors` is not built (app.rs:291-297 prints; cli.rs:45-49 requires per-command flags); ADR-013's claims that the m15 gate "was rewritten" and `vox grant` "is withdrawn" are false in the tree (node_m15_anchor_gate.rs:660-670; cli.rs:397-399). Make ADR-013's tenses match ADR-017's header.
6. **Specify the service-key lifecycle**: when `vox serve` reuses vs mints a key (required for "one name, many ports" and cross-room name stability to be implementable), and record the cross-room correlation a stable name enables.
7. **Decision 1**: justify the keypair against the host-committed random label (`base32(H(host_pk ‖ label))`), which also makes republication impossible without a new losable key — the current rejection only covers guessable derivations.
8. **Strengthen disclosure to match the model's premise**: serve-time audience must name identities, not counts (decision 4's example shows only counts); the consent-grant UX must state that approval confers reach to bound services, since that is the decision the entire design reuses.
9. **`vox grant` deletion**: correct "reach to a non-member was possible" (actor.rs:2735-2743 requires an admitted author), and add to the give-up list the loss of time-bounded grants (`--days`) and of reach-without-read.
10. **Acknowledge the `vox up` shape change**: the built surface is per-room (cli.rs:333-341); the descriptor model is room-global, so decision 5's "unaffected and stand as built" overstates.
