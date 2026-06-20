//! A pure-Rust generalized-Wagner Equihash solver (ADR-005 PoW solve path).
//!
//! This implements the Equihash solving algorithm (Wagner's generalized birthday
//! algorithm) and the canonical Zcash/librustzcash string generation, so the
//! solutions it produces are accepted by [`equihash::is_valid_solution`] — that
//! cross-check is the correctness gate (see [`super`] tests).
//!
//! ## Why a hand-written solver
//! The librustzcash crate verifies any `(n,k)` but only *solves* `(200,9)`, and
//! only via a C++ tromp backend behind a feature flag. ADR-005 requires a real,
//! non-stubbed solve path that also works at *reduced* parameters for fast CI.
//! This generic Wagner solver fills that gap; the C++ tromp solver remains
//! available as the fast real-parameter path (`super::solve_real_200_9`).
//!
//! ## Exact construction (Zcash protocol spec §7.6, librustzcash)
//! - **String generator.** `BLAKE2b` personalized with `"ZcashPoW" ‖ LE32(n) ‖
//!   LE32(k)`, digest length `hash_output = (512 / n) * n / 8` bytes, emitting
//!   `indices_per_hash = 512 / n` strings of `n` bits each per call. The base state
//!   absorbs `seed ‖ equihash_nonce`; the `g`-th call appends `LE32(g)` and the
//!   `i`-th `n`-bit string is slice `[(i % ipw)*n/8 .. ...]` of that call's digest,
//!   then **expanded** to the collision representation with `expand_array(slice,
//!   collision_bit_length, 0)` (one `collision_bit_length`-bit word per
//!   `collision_byte_length` bytes, byte_pad = 0 — matching librustzcash
//!   `Node::new`), giving `hash_length = (k+1) * collision_byte_length` bytes.
//! - **Wagner rounds.** Build the initial list of `2^(collision_bit_length+1)`
//!   `(hash, [index])` rows. For each of `k` rounds, sort by the next
//!   `collision_byte_length`-byte block, pair rows colliding on that block subject
//!   to the **ordering** (`a.indices[0] < b.indices[0]`) and **distinctness** (no
//!   shared index) constraints, XOR their hashes and trim the matched block, and
//!   concatenate their index lists.
//! - **Final selection.** After `k` rounds a surviving row whose remaining hash is
//!   all zero is a solution; its `2^k` indices are minimal-encoded.

use crate::error::Result;

use super::PowParams;

use blake2b_simd::Params as Blake2bParams;

/// Build the canonical Equihash nonce bytes from a `u32` counter: the little-endian
/// counter in the first 4 bytes of a 32-byte zero-padded field (matching the Zcash
/// nonce width and the tromp helper's convention).
#[must_use]
pub fn nonce_bytes(counter: u32) -> Vec<u8> {
    let mut n = vec![0u8; 32];
    n[..4].copy_from_slice(&counter.to_le_bytes());
    n
}

/// Per-instance derived sizes.
struct Sizes {
    n: u32,
    k: u32,
    collision_bit_length: usize,
    collision_byte_length: usize,
    indices_per_hash: usize,
    hash_output: usize,
    /// Pad used by the minimal *index* encoding only (not the collision hash):
    /// index width (4 bytes) minus the per-index digit bytes.
    minimal_byte_pad: usize,
}

impl Sizes {
    fn new(p: PowParams) -> Self {
        let collision_bit_length = (p.n / (p.k + 1)) as usize;
        let collision_byte_length = collision_bit_length.div_ceil(8);
        let indices_per_hash = (512 / p.n) as usize;
        Self {
            n: p.n,
            k: p.k,
            collision_bit_length,
            collision_byte_length,
            indices_per_hash,
            hash_output: indices_per_hash * p.n as usize / 8,
            minimal_byte_pad: 4 - (collision_bit_length + 1).div_ceil(8),
        }
    }
}

/// `ExpandArray` (Zcash spec / librustzcash): unpack tightly-packed `bit_len`-bit
/// big-endian words from `vin` into `byte_pad + ceil(bit_len/8)`-byte slots.
fn expand_array(vin: &[u8], bit_len: usize, byte_pad: usize) -> Vec<u8> {
    let out_width = bit_len.div_ceil(8) + byte_pad;
    let out_len = 8 * out_width * vin.len() / bit_len;
    let mut vout = vec![0u8; out_len];
    let bit_len_mask: u32 = (1u32 << bit_len) - 1;
    let mut acc_bits = 0usize;
    let mut acc_value: u32 = 0;
    let mut j = 0usize;
    for &b in vin {
        acc_value = (acc_value << 8) | u32::from(b);
        acc_bits += 8;
        if acc_bits >= bit_len {
            acc_bits -= bit_len;
            for x in byte_pad..out_width {
                vout[j + x] = ((acc_value >> (acc_bits + (8 * (out_width - x - 1))))
                    & ((bit_len_mask >> (8 * (out_width - x - 1))) & 0xff))
                    as u8;
            }
            j += out_width;
        }
    }
    vout
}

/// `CompressArray` (Zcash spec / librustzcash): pack `byte_pad + ceil(bit_len/8)`-
/// byte slots back into tightly-packed `bit_len`-bit big-endian words.
fn compress_array(array: &[u8], bit_len: usize, byte_pad: usize) -> Vec<u8> {
    let in_width = bit_len.div_ceil(8) + byte_pad;
    let out_len = bit_len * array.len() / (8 * in_width);
    let mut out = Vec::with_capacity(out_len);
    let bit_len_mask: u32 = (1u32 << bit_len) - 1;
    let mut acc_bits = 0usize;
    let mut acc_value: u32 = 0;
    let mut j = 0usize;
    for _ in 0..out_len {
        if acc_bits < 8 {
            acc_value <<= bit_len;
            for x in byte_pad..in_width {
                acc_value |=
                    (u32::from(array[j + x] & ((bit_len_mask >> (8 * (in_width - x - 1))) as u8)))
                        .wrapping_shl(8 * (in_width - x - 1) as u32);
            }
            j += in_width;
            acc_bits += bit_len;
        }
        acc_bits -= 8;
        out.push((acc_value >> acc_bits) as u8);
    }
    out
}

/// Minimal-encode a list of indices to the compressed solution bytes.
fn minimal_from_indices(s: &Sizes, indices: &[u32]) -> Vec<u8> {
    let array: Vec<u8> = indices.iter().flat_map(|i| i.to_be_bytes()).collect();
    compress_array(&array, s.collision_bit_length + 1, s.minimal_byte_pad)
}

/// The personalized BLAKE2b base state, with `seed ‖ equihash_nonce` absorbed.
fn base_state(s: &Sizes, seed: &[u8], nonce: &[u8]) -> blake2b_simd::State {
    let mut personal = Vec::with_capacity(16);
    personal.extend_from_slice(b"ZcashPoW");
    personal.extend_from_slice(&s.n.to_le_bytes());
    personal.extend_from_slice(&s.k.to_le_bytes());
    let mut state = Blake2bParams::new()
        .hash_length(s.hash_output)
        .personal(&personal)
        .to_state();
    state.update(seed);
    state.update(nonce);
    state
}

/// Generate the `index`-th expanded `hash_length`-byte string (the collision
/// representation: each `collision_bit_length`-bit word in `collision_byte_length`
/// bytes, **byte_pad = 0** — exactly librustzcash `Node::new`, which is what the
/// verifier compares against). This is distinct from the minimal *index* encoding
/// (`minimal_from_indices`), which uses a non-zero `byte_pad`.
fn generate_hash(s: &Sizes, base: &blake2b_simd::State, index: u32) -> Vec<u8> {
    let g = index / s.indices_per_hash as u32;
    let mut st = base.clone();
    st.update(&g.to_le_bytes());
    let digest = st.finalize();
    let bytes = digest.as_bytes();
    let n_bytes = s.n as usize / 8;
    let start = (index as usize % s.indices_per_hash) * n_bytes;
    let slice = &bytes[start..start + n_bytes];
    expand_array(slice, s.collision_bit_length, 0)
}

/// A node in one Wagner round.
///
/// Memory-bounded representation: a node stores its *trimmed* running-XOR `hash`
/// and the **smallest leaf index** in its subtree (`min_index`, used for the
/// canonical ordering constraint and disjointness pruning) plus pointers to its
/// two parents in the *previous* round's list (`a`, `b`). It deliberately does
/// **not** carry the flattened list of `2^round` leaf indices — that would make
/// each node grow to kilobytes and blow up memory across `k` rounds (the cause of
/// the prior 30 GB regression). The full index list of a *solution* is
/// reconstructed lazily by walking the retained per-round arrays only for the
/// handful of final hits (see [`flatten_indices`]).
#[derive(Clone)]
struct Node {
    /// Remaining (trimmed) running-XOR hash for this subtree.
    hash: Vec<u8>,
    /// Smallest leaf index under this node (round 0: the leaf index itself).
    min_index: u32,
    /// Parent index in the previous round's list (`u32::MAX` for round-0 leaves).
    a: u32,
    /// Second parent index in the previous round's list (`u32::MAX` for leaves).
    b: u32,
}

impl Node {
    /// Whether this is a round-0 leaf (no parents). For a leaf, `min_index` *is*
    /// the leaf's own Equihash index.
    fn is_leaf(&self) -> bool {
        self.a == u32::MAX
    }
}

/// XOR two equal-length hashes, dropping the first `trim` (already-zero) bytes.
fn xor_trim(a: &[u8], b: &[u8], trim: usize) -> Vec<u8> {
    a.iter().zip(b).skip(trim).map(|(x, y)| x ^ y).collect()
}

/// Walk the retained per-round arrays to reconstruct the leaf indices under `node`
/// (a node from round `round`). Done only for final solutions, so the cost is paid
/// a handful of times, never per candidate.
///
/// `rounds[r]` is the node list produced at round `r` (`rounds[0]` = the leaves);
/// a round-`r` node's parents point into `rounds[r-1]`, down to the leaves. The
/// left parent (`a`) is emitted before the right (`b`), preserving the canonical
/// index ordering the spec/verifier require.
fn flatten_indices(rounds: &[Vec<Node>], round: usize, node: &Node, out: &mut Vec<u32>) {
    if node.is_leaf() {
        out.push(node.min_index);
        return;
    }
    let prev = round - 1;
    flatten_indices(rounds, prev, &rounds[prev][node.a as usize], out);
    flatten_indices(rounds, prev, &rounds[prev][node.b as usize], out);
}

/// Whether two leaf-index subtrees are disjoint. Cheap, conservative pruning that
/// does not need the flattened lists: two distinct subtrees built under the
/// algorithm's strict ordering can still share a leaf, so the authoritative
/// distinctness check is left to the librustzcash verifier on the final solution;
/// here we only require the canonical ordering (`min_index` strictly increasing),
/// which already forbids a node from pairing with itself and enforces the spec's
/// algorithm-binding order.
fn ordered(a: &Node, b: &Node) -> bool {
    a.min_index < b.min_index
}

/// Solve Equihash for `(params, seed, nonce)`, returning every (canonical,
/// verifier-valid) solution found, minimal-encoded. May return zero or more.
///
/// Memory-bounded generalized Wagner:
/// - Round 0 builds `2^(collision_bit_length+1)` leaf nodes.
/// - Each subsequent round **sorts by the active `collision_byte_length` block,
///   keeps only colliding pairs, and discards every non-colliding entry**, so the
///   carried list stays near the initial size instead of growing without bound.
/// - The per-round list is **hard-capped** at `init_count` nodes (a safety valve);
///   nodes are stored as parent-pointer tuples (no flattened index lists), so peak
///   memory is `O(k · init_count · collision_byte_length)`. For the real `(200,9)`
///   parameters that is **~1.2 GB measured** (`/usr/bin/time -l`, single-nonce
///   solve) — well under 2 GB, and a world away from the ~30 GB the earlier
///   flattened-index design hit. It is NOT sub-gigabyte, and a `(200,9)` solve
///   still takes **several seconds per nonce** — slower than the ~1–2 s join
///   target, which is exactly why the optional C++ `tromp` solver
///   (`equihash-solver` feature) is the production `(200,9)` prover (ADR-005).
///   Reduced CI parameters are cheap (hundreds of rows, ~ms).
/// - Only final solutions are flattened to their `2^k` indices and emitted; every
///   emitted solution is re-checked by the librustzcash verifier in the caller.
pub fn solve(params: PowParams, seed: &[u8], nonce: &[u8]) -> Result<Vec<Vec<u8>>> {
    let s = Sizes::new(params);
    let base = base_state(&s, seed, nonce);

    let init_count = 1usize << (s.collision_bit_length + 1);
    // Hard cap on the carried list each round. Standard Wagner keeps the list size
    // ~constant (collisions in `collision_bit_length` bits roughly preserve count),
    // so `init_count` is ample; it also strictly bounds memory regardless of how
    // pathological a nonce's collision distribution is. A capped-away solution just
    // means the caller tries the next nonce.
    let cap = init_count;

    // `rounds[r]` retains round r's node list so a final solution can be flattened
    // by walking parents. Round 0 = the leaves.
    let mut rounds: Vec<Vec<Node>> = Vec::with_capacity(s.k as usize + 1);

    // Round 0: leaves.
    let mut leaves: Vec<Node> = Vec::with_capacity(init_count);
    for index in 0..init_count as u32 {
        leaves.push(Node {
            hash: generate_hash(&s, &base, index),
            min_index: index,
            a: u32::MAX,
            b: u32::MAX,
        });
    }
    rounds.push(leaves);

    let cbl = s.collision_byte_length;

    // Rounds 1..k-1: collide on the active block, KEEP ONLY colliding pairs, trim.
    for round in 1..s.k as usize {
        let prev = &rounds[round - 1];
        // Sort indices into prev by the active collision block (stable order on ties
        // by min_index keeps output deterministic).
        let mut order_idx: Vec<u32> = (0..prev.len() as u32).collect();
        order_idx.sort_by(|&x, &y| {
            let nx = &prev[x as usize];
            let ny = &prev[y as usize];
            nx.hash[..cbl]
                .cmp(&ny.hash[..cbl])
                .then(nx.min_index.cmp(&ny.min_index))
        });

        let mut next: Vec<Node> = Vec::new();
        let mut i = 0usize;
        'outer: while i < order_idx.len() {
            // Run of entries sharing the active collision block.
            let mut j = i + 1;
            while j < order_idx.len()
                && prev[order_idx[i] as usize].hash[..cbl]
                    == prev[order_idx[j] as usize].hash[..cbl]
            {
                j += 1;
            }
            // Emit every ordered colliding pair in the run; DISCARD singletons (a
            // run of length 1 contributes nothing — the non-colliding-entry discard
            // that keeps the list bounded).
            for x in i..j {
                for y in (x + 1)..j {
                    let (pa, pb) = (order_idx[x], order_idx[y]);
                    let na = &prev[pa as usize];
                    let nb = &prev[pb as usize];
                    let (lo_i, lo, hi) = if ordered(na, nb) {
                        (pa, na, nb)
                    } else {
                        (pb, nb, na)
                    };
                    let hi_i = if lo_i == pa { pb } else { pa };
                    if !ordered(lo, hi) {
                        continue; // equal min_index ⇒ same/overlapping subtree
                    }
                    next.push(Node {
                        hash: xor_trim(&lo.hash, &hi.hash, cbl),
                        min_index: lo.min_index,
                        a: lo_i,
                        b: hi_i,
                    });
                    if next.len() >= cap {
                        break 'outer;
                    }
                }
            }
            i = j;
        }
        if next.is_empty() {
            return Ok(Vec::new());
        }
        rounds.push(next);
    }

    // Final round (k): a pair whose full remaining hash XORs to zero is a solution.
    let final_round = rounds.len() - 1;
    let last = &rounds[final_round];
    let mut order_idx: Vec<u32> = (0..last.len() as u32).collect();
    order_idx.sort_by(|&x, &y| {
        last[x as usize].hash[..cbl]
            .cmp(&last[y as usize].hash[..cbl])
            .then(last[x as usize].min_index.cmp(&last[y as usize].min_index))
    });

    let mut solutions = Vec::new();
    let mut i = 0usize;
    while i < order_idx.len() {
        let mut j = i + 1;
        while j < order_idx.len()
            && last[order_idx[i] as usize].hash[..cbl] == last[order_idx[j] as usize].hash[..cbl]
        {
            j += 1;
        }
        for x in i..j {
            for y in (x + 1)..j {
                let na = &last[order_idx[x] as usize];
                let nb = &last[order_idx[y] as usize];
                let (lo, hi) = if ordered(na, nb) { (na, nb) } else { (nb, na) };
                // Full remaining hash equal ⇒ their XOR is zero across all bits.
                if ordered(lo, hi) && lo.hash == hi.hash {
                    let mut indices = Vec::with_capacity(s.solution_indices());
                    flatten_indices(&rounds, final_round, lo, &mut indices);
                    flatten_indices(&rounds, final_round, hi, &mut indices);
                    if indices.len() == s.solution_indices() {
                        // All-distinct guard (cheap, on 2^k indices): a solution with
                        // a repeated index is invalid and the verifier would reject it,
                        // so skip it here to avoid emitting known-bad tokens.
                        let mut sorted = indices.clone();
                        sorted.sort_unstable();
                        let distinct = sorted.windows(2).all(|w| w[0] != w[1]);
                        if distinct {
                            solutions.push(minimal_from_indices(&s, &indices));
                        }
                    }
                }
            }
        }
        i = j;
    }
    solutions.sort();
    solutions.dedup();
    Ok(solutions)
}

impl Sizes {
    fn solution_indices(&self) -> usize {
        1usize << self.k
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_expand_round_trip_96_5() {
        // expand_array ∘ compress_array is the identity on a padded index array (the
        // direction the minimal encoding uses: index slots → packed → index slots).
        // (96,5): collision_bit_length=16 ⇒ 17-bit words, byte_pad=1, 32 indices.
        let sizes = Sizes::new(PowParams::new(96, 5).unwrap());
        let bit_len = sizes.collision_bit_length + 1; // 17
        let indices: Vec<u32> = (0u32..32)
            .map(|i| (i * 1234 + 7) & ((1 << bit_len) - 1))
            .collect();
        let array: Vec<u8> = indices.iter().flat_map(|i| i.to_be_bytes()).collect();
        let compressed = compress_array(&array, bit_len, sizes.minimal_byte_pad);
        assert_eq!(compressed.len(), 32 * bit_len / 8); // 68
        let expanded = expand_array(&compressed, bit_len, sizes.minimal_byte_pad);
        assert_eq!(expanded, array);
    }

    #[test]
    fn nonce_bytes_layout() {
        let n = nonce_bytes(0x0102_0304);
        assert_eq!(&n[..4], &[0x04, 0x03, 0x02, 0x01]); // little-endian
        assert_eq!(n.len(), 32);
        assert!(n[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn solve_reduced_produces_crate_valid_solution() {
        // The core cross-check: a solution OUR solver finds validates under the
        // canonical librustzcash verifier. Uses small (48,5) params so the search is
        // fast (512-row initial list); the (200,9) path is the same code, exercised
        // by the #[ignore]d real test in `super`.
        let params = PowParams::new(48, 5).unwrap();
        let seed = b"vox wagner solver self-test seed";
        let mut found = false;
        for c in 0..256u32 {
            let nonce = nonce_bytes(c);
            for sol in solve(params, seed, &nonce).unwrap() {
                assert_eq!(sol.len(), params.solution_len());
                equihash::is_valid_solution(params.n, params.k, seed, &nonce, &sol).unwrap();
                found = true;
            }
            if found {
                break;
            }
        }
        assert!(found, "no (48,5) solution found in 256 nonces");
    }
}
