//! A pure-Rust generalized-Wagner Equihash solver (ADR-005 PoW solve path) with a
//! **bucket-sorted, flat-memory layout** (the design tromp's `equi_miner` made
//! standard, re-derived here from the algorithm — no C code is ported).
//!
//! This implements the Equihash solving algorithm (Wagner's generalized birthday
//! algorithm) and the canonical Zcash/librustzcash string generation, so the
//! solutions it produces are accepted by [`equihash::is_valid_solution`] — that
//! cross-check is the correctness gate (see [`super`] tests).
//!
//! ## Why a hand-written solver
//! The librustzcash crate verifies any `(n,k)` but only *solves* `(200,9)`, and
//! only via a C++ backend. Vox is Rust-only (ADR-001 #10; the C++ carve-out was
//! rejected by the decider 2026-09-19), and ADR-005 requires a real, non-stubbed
//! solve path that also works at *reduced* parameters for fast CI. This solver is
//! therefore the **only** prover, at every parameter set.
//!
//! ## Exact construction (Zcash protocol spec §7.6, librustzcash)
//! - **String generator.** `BLAKE2b` personalized with `"ZcashPoW" ‖ LE32(n) ‖
//!   LE32(k)`, digest length `hash_output = (512 / n) * n / 8` bytes, emitting
//!   `indices_per_hash = 512 / n` strings of `n` bits each per call. The base state
//!   absorbs `seed ‖ equihash_nonce`; the `g`-th call appends `LE32(g)` and the
//!   `i`-th `n`-bit string is slice `[(i % ipw)*n/8 .. ...]` of that call's digest,
//!   then **expanded** to the collision representation with `expand_array(slice,
//!   collision_bit_length, 0)` (one `collision_bit_length`-bit *digit* per
//!   `collision_byte_length` bytes, byte_pad = 0 — matching librustzcash
//!   `Node::new`), giving `k + 1` digits.
//! - **Wagner rounds.** Rounds `0 .. k-1` each pair entries that collide on digit
//!   `r`, XOR the remaining digits and drop digit `r`; the final round (`k-1`) pairs
//!   entries that collide on **both** remaining digits (`k-1` and `k`), i.e. whose
//!   full remaining hash XORs to zero — a solution of `2^k` leaves.
//! - **Canonical form.** A solution's `2^k` indices are ordered so that at every
//!   tree node the left subtree's first index is smaller than the right's, must be
//!   pairwise distinct, and are minimal-encoded (`compress_array` with the index
//!   width `collision_bit_length + 1`).
//!
//! ## Memory layout (the whole point)
//! Round `r`'s entries live in a flat byte buffer of `NBUCKETS × NSLOTS` fixed-size
//! slots, bucketed by the top `BUCKBITS` bits of digit `r`; a slot is
//! `[rest byte ‖ digits r+1..k]` where `rest` is the low `RESTBITS` bits of digit
//! `r` (so an in-bucket collision is a byte compare). Two such buffers alternate
//! between rounds. For each round `1 ..= k-1` a separate `u32` array records every
//! slot's parent pair `(bucket, slot_a, slot_b)` in the previous round, and round 0
//! records leaf indices; that is all a solution needs to be expanded, and it is
//! done only for the handful of final hits. Nothing is heap-allocated per entry
//! and nothing is sorted: per bucket, a `2^RESTBITS`-entry chained table on the
//! rest byte finds the colliding pairs in one pass. A bucket that fills drops
//! further entries (a bounded, rare loss of solution candidates — the caller tries
//! the next nonce), so memory is fixed by the parameters alone:
//! `NBUCKETS × NSLOTS × (stride_0 + stride_1) + k × NBUCKETS × NSLOTS × 4`.
//! At `(200,9)` with 12 bucket bits and ≈ 603 slots that is ≈ 220 MB of buffers;
//! **measured 2026-09-19: ≈ 1.1 s per nonce, 245 MB peak RSS, ≈ 2.5 solutions
//! per nonce** (release build, Apple-silicon laptop core, `spike_pow`), against
//! 7.5 s / 1.65 GB for the previous parent-pointer layout. Reduced CI parameters
//! are cheap (~ms).

use crate::error::{Error, Result};

use super::PowParams;

use blake2b_simd::Params as Blake2bParams;

/// Build the canonical Equihash nonce bytes from a `u32` counter: the little-endian
/// counter in the first 4 bytes of a 32-byte zero-padded field (matching the Zcash
/// nonce width).
#[must_use]
pub fn nonce_bytes(counter: u32) -> Vec<u8> {
    let mut n = vec![0u8; 32];
    n[..4].copy_from_slice(&counter.to_le_bytes());
    n
}

/// Headroom over the expected per-bucket occupancy, in standard deviations
/// (bucket occupancy is Poisson-like): `nslots = mean + HEADROOM_SIGMAS·√mean`.
/// Four sigmas keeps overflow drops negligible at every parameter set.
const HEADROOM_SIGMAS: f64 = 4.0;

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
    /// Number of digits (`k + 1`).
    ndigits: usize,
    /// Initial list size `2^(collision_bit_length + 1)`.
    nhashes: usize,
    /// Bucket bits: the top bits of a digit select the bucket.
    buck_bits: u32,
    /// Rest bits: the low bits of a digit (`≤ 8`, stored in one byte).
    rest_bits: u32,
    nbuckets: usize,
    nslots: usize,
    /// Bits needed to address a slot within a bucket.
    slot_bits: u32,
}

impl Sizes {
    fn new(p: PowParams) -> Result<Self> {
        let collision_bit_length = (p.n / (p.k + 1)) as usize;
        let collision_byte_length = collision_bit_length.div_ceil(8);
        let indices_per_hash = (512 / p.n) as usize;
        let ndigits = p.k as usize + 1;
        let nhashes = 1usize << (collision_bit_length + 1);
        // Rest bits fit one byte; small digits split in half so buckets stay useful.
        let rest_bits = if collision_bit_length >= 12 {
            8
        } else {
            (collision_bit_length / 2) as u32
        };
        let buck_bits = collision_bit_length as u32 - rest_bits;
        let nbuckets = 1usize << buck_bits;
        let mean = nhashes as f64 / nbuckets as f64;
        let nslots = (mean + HEADROOM_SIGMAS * mean.sqrt()).ceil() as usize;
        let nslots = nslots.max(2).min(u16::MAX as usize - 1);
        let slot_bits = usize::BITS - (nslots - 1).leading_zeros();
        Ok(Self {
            n: p.n,
            k: p.k,
            collision_bit_length,
            collision_byte_length,
            indices_per_hash,
            hash_output: indices_per_hash * p.n as usize / 8,
            minimal_byte_pad: 4 - (collision_bit_length + 1).div_ceil(8),
            ndigits,
            nhashes,
            buck_bits,
            rest_bits,
            nbuckets,
            nslots,
            slot_bits,
        })
    }

    fn solution_indices(&self) -> usize {
        1usize << self.k
    }

    /// Slot byte width at round `r`: the rest byte plus digits `r+1 ..= k`.
    fn stride(&self, r: usize) -> usize {
        1 + self.collision_byte_length * (self.ndigits - 1 - r)
    }

    /// Total slots per layer.
    fn layer_slots(&self) -> usize {
        self.nbuckets * self.nslots
    }

    /// Bits a packed parent reference needs.
    fn ref_bits(&self) -> u32 {
        self.buck_bits + 2 * self.slot_bits
    }

    /// Fixed peak memory of the solver's large buffers, in bytes (documentation +
    /// test aid; the two live hash layers and every round's ref array).
    #[cfg(test)]
    fn memory_bytes(&self) -> usize {
        let slots = self.layer_slots();
        let ref_width = if self.ref_bits() <= 32 { 4 } else { 8 };
        slots * (self.stride(0) + self.stride(1)) + (self.k as usize) * slots * ref_width
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

/// The value of the `collision_byte_length`-byte big-endian digit at `bytes`.
fn digit_value(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b))
}

/// Per-round parent references: `(bucket, slot_a, slot_b)` packed into 32 bits
/// when they fit (every production parameter set), else 64.
enum Refs {
    U32(Vec<u32>),
    U64(Vec<u64>),
}

impl Refs {
    fn new(s: &Sizes) -> Self {
        let n = s.layer_slots();
        if s.ref_bits() <= 32 {
            Self::U32(vec![0; n])
        } else {
            Self::U64(vec![0; n])
        }
    }

    fn set(&mut self, i: usize, v: u64) {
        match self {
            Self::U32(v32) => v32[i] = v as u32,
            Self::U64(v64) => v64[i] = v,
        }
    }

    fn get(&self, i: usize) -> u64 {
        match self {
            Self::U32(v32) => u64::from(v32[i]),
            Self::U64(v64) => v64[i],
        }
    }
}

/// The solver state for one `(seed, nonce)`.
struct Solver {
    s: Sizes,
    /// Two alternating hash layers (`layers[r % 2]` holds round `r`).
    layers: [Vec<u8>; 2],
    /// Per-bucket occupancy of the layer being written.
    counts: Vec<u16>,
    /// Per-bucket occupancy of the layer being read.
    counts_prev: Vec<u16>,
    /// `refs[0]` = leaf index per round-0 slot; `refs[r]` = packed parent pair per
    /// round-`r` slot, `1 ..= k-1`.
    refs: Vec<Refs>,
    /// Entries dropped because their bucket was full (diagnostic).
    dropped: usize,
}

impl Solver {
    fn new(s: Sizes) -> Self {
        let slots = s.layer_slots();
        let layers = [
            vec![0u8; slots * s.stride(0)],
            vec![0u8; slots * s.stride(1)],
        ];
        let counts = vec![0u16; s.nbuckets];
        let counts_prev = vec![0u16; s.nbuckets];
        Self {
            s,
            layers,
            counts,
            counts_prev,
            refs: Vec::new(),
            dropped: 0,
        }
    }

    fn pack_ref(&self, bucket: usize, a: usize, b: usize) -> u64 {
        let sb = self.s.slot_bits;
        ((bucket as u64) << (2 * sb)) | ((a as u64) << sb) | (b as u64)
    }

    fn unpack_ref(&self, r: u64) -> (usize, usize, usize) {
        let sb = self.s.slot_bits;
        let mask = (1u64 << sb) - 1;
        (
            (r >> (2 * sb)) as usize,
            ((r >> sb) & mask) as usize,
            (r & mask) as usize,
        )
    }

    /// Place an entry into the layer for round `round`: `digit` is that round's
    /// digit (selects bucket + rest), `rest_digits` are digits `round+1 ..= k`.
    /// Returns the slot index within the bucket, or `None` if the bucket is full.
    fn place(&mut self, round: usize, digit: u32, rest_digits: &[u8]) -> Option<(usize, usize)> {
        let bucket = (digit >> self.s.rest_bits) as usize;
        let rest = (digit & ((1u32 << self.s.rest_bits) - 1)) as u8;
        let cnt = usize::from(self.counts[bucket]);
        if cnt >= self.s.nslots {
            self.dropped += 1;
            return None;
        }
        let stride = self.s.stride(round);
        let slot = bucket * self.s.nslots + cnt;
        let off = slot * stride;
        let layer = &mut self.layers[round % 2];
        layer[off] = rest;
        layer[off + 1..off + stride].copy_from_slice(rest_digits);
        self.counts[bucket] = (cnt + 1) as u16;
        Some((bucket, cnt))
    }

    /// Round 0: generate every leaf string and bucket it by digit 0.
    fn fill_leaves(&mut self, base: &blake2b_simd::State) {
        let s_ndigits = self.s.ndigits;
        let cbl = self.s.collision_byte_length;
        let n_bytes = self.s.n as usize / 8;
        let ipw = self.s.indices_per_hash;
        let mut refs0 = Refs::new(&self.s);
        let mut g: u32 = 0;
        let mut index: usize = 0;
        while index < self.s.nhashes {
            let mut st = base.clone();
            st.update(&g.to_le_bytes());
            let digest = st.finalize();
            let bytes = digest.as_bytes();
            for i in 0..ipw {
                if index >= self.s.nhashes {
                    break;
                }
                let slice = &bytes[i * n_bytes..(i + 1) * n_bytes];
                let digits = expand_array(slice, self.s.collision_bit_length, 0);
                debug_assert_eq!(digits.len(), s_ndigits * cbl);
                let d0 = digit_value(&digits[..cbl]);
                if let Some((bucket, slot)) = self.place(0, d0, &digits[cbl..]) {
                    refs0.set(bucket * self.s.nslots + slot, index as u64);
                }
                index += 1;
            }
            g += 1;
        }
        self.refs.push(refs0);
    }

    /// One collision round: read round `round`, write round `round + 1`.
    fn collide(&mut self, round: usize) {
        let s_nb = self.s.nbuckets;
        let s_ns = self.s.nslots;
        let cbl = self.s.collision_byte_length;
        let stride_in = self.s.stride(round);
        let stride_out = self.s.stride(round + 1);
        let rest_table = 1usize << self.s.rest_bits;
        std::mem::swap(&mut self.counts, &mut self.counts_prev);
        self.counts.iter_mut().for_each(|c| *c = 0);
        let mut refs_next = Refs::new(&self.s);
        let mut heads = vec![u16::MAX; rest_table];
        let mut next = vec![u16::MAX; s_ns];
        let mut xor = vec![0u8; stride_in - 1];

        for bucket in 0..s_nb {
            let cnt = usize::from(self.counts_prev[bucket]);
            if cnt < 2 {
                continue;
            }
            heads.iter_mut().for_each(|h| *h = u16::MAX);
            let base_off = bucket * s_ns * stride_in;
            for i in 0..cnt {
                let off_i = base_off + i * stride_in;
                let rest_i = usize::from(self.layers[round % 2][off_i]);
                let mut j = heads[rest_i];
                while j != u16::MAX {
                    let off_j = base_off + usize::from(j) * stride_in;
                    // XOR the remaining digits (round+1 ..= k) of the pair.
                    {
                        let layer = &self.layers[round % 2];
                        let a = &layer[off_i + 1..off_i + stride_in];
                        let b = &layer[off_j + 1..off_j + stride_in];
                        for ((x, &p), &q) in xor.iter_mut().zip(a).zip(b) {
                            *x = p ^ q;
                        }
                    }
                    let d_next = digit_value(&xor[..cbl]);
                    if let Some((nb, ns)) = self.place(round + 1, d_next, &xor[cbl..]) {
                        let packed = self.pack_ref(bucket, usize::from(j), i);
                        refs_next.set(nb * s_ns + ns, packed);
                    }
                    j = next[usize::from(j)];
                }
                next[i] = heads[rest_i];
                heads[rest_i] = i as u16;
            }
        }
        debug_assert_eq!(stride_out, self.s.stride(round + 1));
        self.refs.push(refs_next);
    }

    /// The final round (`k-1`): pairs colliding on the rest byte of digit `k-1`
    /// **and** all of digit `k` XOR to zero — solutions. Returns `(bucket, a, b)`
    /// slot pairs in the round-`k-1` layer.
    fn final_pairs(&mut self, round: usize) -> Vec<(usize, usize, usize)> {
        let s_nb = self.s.nbuckets;
        let s_ns = self.s.nslots;
        let stride_in = self.s.stride(round);
        debug_assert_eq!(stride_in, 1 + self.s.collision_byte_length);
        let rest_table = 1usize << self.s.rest_bits;
        std::mem::swap(&mut self.counts, &mut self.counts_prev);
        let mut heads = vec![u16::MAX; rest_table];
        let mut next = vec![u16::MAX; s_ns];
        let mut out = Vec::new();
        let layer = &self.layers[round % 2];
        for bucket in 0..s_nb {
            let cnt = usize::from(self.counts_prev[bucket]);
            if cnt < 2 {
                continue;
            }
            heads.iter_mut().for_each(|h| *h = u16::MAX);
            let base_off = bucket * s_ns * stride_in;
            for i in 0..cnt {
                let off_i = base_off + i * stride_in;
                let rest_i = usize::from(layer[off_i]);
                let last_i = &layer[off_i + 1..off_i + stride_in];
                let mut j = heads[rest_i];
                while j != u16::MAX {
                    let off_j = base_off + usize::from(j) * stride_in;
                    if &layer[off_j + 1..off_j + stride_in] == last_i {
                        out.push((bucket, usize::from(j), i));
                    }
                    j = next[usize::from(j)];
                }
                next[i] = heads[rest_i];
                heads[rest_i] = i as u16;
            }
        }
        out
    }

    /// Expand the leaves under slot `(bucket, slot)` of round `round`, in canonical
    /// order (at every node the subtree with the smaller first index comes first).
    fn expand(&self, round: usize, bucket: usize, slot: usize, out: &mut Vec<u32>) {
        let idx = bucket * self.s.nslots + slot;
        if round == 0 {
            out.push(self.refs[0].get(idx) as u32);
            return;
        }
        let (pb, a, b) = self.unpack_ref(self.refs[round].get(idx));
        let start = out.len();
        self.expand(round - 1, pb, a, out);
        let mid = out.len();
        self.expand(round - 1, pb, b, out);
        if out[start] > out[mid] {
            let half = mid - start;
            let (l, r) = out[start..].split_at_mut(half);
            l.swap_with_slice(&mut r[..half]);
        }
    }
}

/// Solve Equihash for `(params, seed, nonce)`, returning every (canonical,
/// verifier-valid) solution found, minimal-encoded. May return zero or more.
///
/// See the module docs for the layout. Peak memory is fixed by the parameters
/// (`Sizes::memory_bytes`); a full bucket drops entries rather than growing.
pub fn solve(params: PowParams, seed: &[u8], nonce: &[u8]) -> Result<Vec<Vec<u8>>> {
    let s = Sizes::new(params)?;
    if s.k < 3 {
        return Err(Error::JoinPowInvalid);
    }
    let base = base_state(&s, seed, nonce);
    let mut solver = Solver::new(s);
    solver.fill_leaves(&base);

    let k = solver.s.k as usize;
    for round in 0..k - 1 {
        solver.collide(round);
    }
    let pairs = solver.final_pairs(k - 1);

    let want = solver.s.solution_indices();
    let mut solutions = Vec::new();
    let mut indices = Vec::with_capacity(want);
    for (bucket, a, b) in pairs {
        indices.clear();
        solver.expand(k - 1, bucket, a, &mut indices);
        let mid = indices.len();
        solver.expand(k - 1, bucket, b, &mut indices);
        if indices.len() != want {
            continue;
        }
        if indices[0] > indices[mid] {
            let (l, r) = indices.split_at_mut(mid);
            l.swap_with_slice(&mut r[..mid]);
        }
        // All-distinct guard: a solution with a repeated index is invalid and the
        // verifier would reject it, so skip it here.
        let mut sorted = indices.clone();
        sorted.sort_unstable();
        if sorted.windows(2).all(|w| w[0] != w[1]) {
            solutions.push(minimal_from_indices(&solver.s, &indices));
        }
    }
    solutions.sort();
    solutions.dedup();
    Ok(solutions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_expand_round_trip_96_5() {
        // expand_array ∘ compress_array is the identity on a padded index array (the
        // direction the minimal encoding uses: index slots → packed → index slots).
        // (96,5): collision_bit_length=16 ⇒ 17-bit words, byte_pad=1, 32 indices.
        let sizes = Sizes::new(PowParams::new(96, 5).unwrap()).unwrap();
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
    fn layout_sizes_at_real_and_reduced_params() {
        // (200,9): 20-bit digits split 12 bucket bits + 8 rest bits; 2^21 leaves;
        // 32-bit parent refs fit; the fixed memory budget is under 256 MiB.
        let s = Sizes::new(PowParams::DEFAULT).unwrap();
        assert_eq!(s.collision_bit_length, 20);
        assert_eq!(s.collision_byte_length, 3);
        assert_eq!(s.ndigits, 10);
        assert_eq!(s.nhashes, 1 << 21);
        assert_eq!((s.buck_bits, s.rest_bits), (12, 8));
        assert_eq!(s.nbuckets, 4096);
        assert!(s.nslots >= 512 && s.nslots <= 1024, "nslots={}", s.nslots);
        assert!(s.ref_bits() <= 32);
        assert_eq!(s.stride(0), 1 + 3 * 9);
        assert_eq!(s.stride(8), 1 + 3);
        assert!(
            s.memory_bytes() <= 256 * 1024 * 1024,
            "memory {} B",
            s.memory_bytes()
        );
        // (48,5): 8-bit digits split 4 + 4; 512 leaves; tiny.
        let s = Sizes::new(PowParams::new(48, 5).unwrap()).unwrap();
        assert_eq!((s.buck_bits, s.rest_bits), (4, 4));
        assert_eq!(s.nhashes, 512);
        assert!(s.ref_bits() <= 32);
        // (144,5): 24-bit digits, 2^25 leaves — refs need 64 bits and get them.
        let s = Sizes::new(PowParams::new(144, 5).unwrap()).unwrap();
        assert!(s.ref_bits() > 32);
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

    #[test]
    fn solve_96_5_solutions_all_verify() {
        // A mid-size parameter set with a 16-bit digit (8 + 8 split) and multiple
        // solutions per nonce: every emitted solution must verify, none may be a
        // duplicate.
        let params = PowParams::new(96, 5).unwrap();
        let seed = b"vox wagner solver 96-5 seed";
        let mut total = 0;
        for c in 0..4u32 {
            let nonce = nonce_bytes(c);
            let sols = solve(params, seed, &nonce).unwrap();
            for w in sols.windows(2) {
                assert_ne!(w[0], w[1]);
            }
            for sol in &sols {
                equihash::is_valid_solution(params.n, params.k, seed, &nonce, sol).unwrap();
            }
            total += sols.len();
        }
        assert!(total > 0, "expected some (96,5) solutions over 4 nonces");
    }
}
