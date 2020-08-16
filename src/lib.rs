//! A fast, deterministic, non-cryptographic hash for use in hash tables.
//!
//! ZwoHash implements a very fast hash algorithm optimized for the use in hash tables. It has low
//! per-hash overhead, which is important when hashing small keys. It is non-cryptographic and
//! deterministic and as such not suited for inserting untrusted user-provided input into hash
//! tables, unless other denial of service countermeasures are taken. As such it covers the same use
//! cases as [rustc's FxHash][rustc_hash].
//!
//! Compared to FxHash, ZwoHash provides essentially the same hashing speed while aiming for more
//! uniform outputs. When used in a hash table ZwoHash is almost always able to match the
//! performance of FxHash while outperforming it by quite a bit for some common inputs for which
//! FxHash's output is particularly poor.
//!
//! The hash algorithm used by ZwoHash is very similar to that of FxHash, both process one `usize`
//! at a time and perform the same number and kind of operations per `usize`. ZwoHash though,
//! replaces the last iteration with a slightly more expensive operation that provides better output
//! guarantees. The additional overhead (independent of the size of the hashed data) consists of
//! performing a wide multiplication instead of a truncated multiplication and one additional
//! subtraction. This is very little overhead, and almost doesn't register, even when benchmarking
//! the hash function in isolation on integer keys.
//!
//! ZwoHash guarantees that any input bit can affect any bit of the output. FxHash does not
//! guarantee this, and even beyond that, ZwoHash's output is more uniform. When used in a hash
//! table, this often reduces the number of collisions and thus the number of required probes for
//! each access. This can result in ZwoHash outperforming FxHash in that setting.
//!
//! Sometimes, given inputs for which FxHash is especially ill-suited, ZwoHash outperforms FxHash by
//! a large margin. This includes integer keys that all are a multiple of a power of two, floating
//! point values with a short base-2 representation, pointers returned from the allocator and other
//! inputs that only differ in the higher bits of the last processed `usize`.
//!
//! [rustc_hash]: https://crates.io/crates/rustc-hash
#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(any(feature = "std"))]
use core::hash::BuildHasherDefault;
use core::{convert::TryInto, hash::Hasher, ptr};

#[cfg(any(feature = "std"))]
use std::collections;

/// A [`collections::HashMap`] using [`ZwoHasher`] to compute hashes.
#[cfg(all(feature = "std"))]
pub type HashMap<K, V> = collections::HashMap<K, V, BuildHasherDefault<ZwoHasher>>;
/// A [`collections::HashSet`] using [`ZwoHasher`] to compute hashes.
#[cfg(all(feature = "std"))]
pub type HashSet<V> = collections::HashSet<V, BuildHasherDefault<ZwoHasher>>;

/// A fast, deterministic, non-cryptographic hash for use in hash tables.
///
/// Can be constructed using [`Default`] and then used using [`Hasher`]. See the [`crate`]'s
/// documentation for more information.
pub struct ZwoHasher {
    state: usize,
}

impl Default for ZwoHasher {
    #[inline]
    fn default() -> ZwoHasher {
        ZwoHasher { state: 0 }
    }
}

// Taken from Pierre L’Ecuyer. 1999. Tables of Linear Congruential Generators of Different Sizes and
// Good Lattice Structure.
//
// This is a bit silly, because the xoring of input words and the rotation (see write_usize below)
// means that this isn't really related to an LCG. Nevertheless these constants seem to perform
// well, slightly better than a few other choices I tried. It might be worth to more systematically
// explore the possible choices here.
#[cfg(target_pointer_width = "64")]
const M: usize = 0x2545f4914f6cdd1d;
#[cfg(target_pointer_width = "32")]
const M: usize = 0x2c9277b5;

// These values are chosen as the nearest integer to `bits/phi` that is coprime to `bits`. being
// coprime to `bits` means the commulated rotation offset cycles through all bit positions before
// repeating, being close to `bits/phi` means the sequence of commulated rotation offsets is
// distributed evenly.
#[cfg(target_pointer_width = "64")]
const R: u32 = 41;
#[cfg(target_pointer_width = "32")]
const R: u32 = 21;

#[cfg(target_pointer_width = "64")]
type WideInt = u128;
#[cfg(target_pointer_width = "32")]
type WideInt = u64;

const USIZE_BITS: u32 = 0usize.count_zeros();
const USIZE_BYTES: usize = core::mem::size_of::<usize>();

impl Hasher for ZwoHasher {
    #[inline]
    fn write_usize(&mut self, i: usize) {
        // Every other write is implemented via this function. It differs from FxHash in the used
        // constants and in that we xor the input word at the end. We can do this as we do
        // additional mixing in finish, which FxHash doesn't do. This way if the first write_usize
        // is inlined, the wrapping_mul and rotate_right get const evaluated.
        self.state = self.state.wrapping_mul(M).rotate_right(R) ^ i;
    }

    #[inline]
    fn finish(&self) -> u64 {
        // Our state update (in write_usize) doesn't mix the bits very much. The wrapping_mul only
        // allows lower bits to affect higher bits, which is somewhat mitigated by the rotate_right,
        // but that still requires multiple updates to really mix the bits.
        //
        // Additionally the last added word isn't mixed at all.
        //
        // We can work around both these problems by performing a slightly more expensive but much
        // better mixing here at the end. To do that we don't use wrapping_mul but instead perform a
        // wide multiplication and subtract the high from the low resutling word to get the final
        // hash. This allows any bit of the final state to affect any bit of the output hash.
        //
        // For hashes of short values, e.g. of single ints, this is slightly more expensive than
        // FxHash, even with more const evaluation for the first write_usize. For longer values this
        // is quickly amortized.
        //
        // See the test at the end of this file of what mixing properties this guarantees.
        let wide = (self.state as WideInt) * (M as WideInt);
        (wide as usize).wrapping_sub((wide >> USIZE_BITS) as usize) as u64
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        // Working on a local copy might make the job of the optimizer compling this easier, but I
        // haven't checked that, this is cargo culted from rustc's FxHash
        let mut copy = ZwoHasher { state: self.state };

        // We write the length of the slice as first input. We do this since we're zero-padding the
        // slice the a multiple of `USIZE_BYTES` bytes, and we don't want this to cause collisions
        // when the input slice is already zero-padded.
        //
        // We do this as first step for two reasons:
        // 1) If this slice has a known length at compile time and is the first thing that is
        //    hashed, this step can be completely const evaluated.
        // 2) If the slice is not known at compile time but is the first thing that is hashed, this
        //    can be partially const evaluated.
        copy.write_usize(bytes.len());

        // If we have less than BYTES trailing bytes, we fill up partial_chunk with them and
        // then process that. We pad with nonzero bytes, so we don't produce collisions for
        // slices that have the same prefix and are zero padded.

        let mut chunks = bytes.chunks_exact(USIZE_BYTES);

        for full_chunk in &mut chunks {
            // This try_into always succeeds and the size check is optimized away
            let full_chunk: [u8; USIZE_BYTES] = full_chunk.try_into().unwrap();
            copy.write_usize(usize::from_ne_bytes(full_chunk));
        }

        let partial_chunk = chunks.remainder();

        // For the trailing bytes, we fill up partial_chunk with them and then process that. We also
        // process the partial_chunk if it is empty, this avoids a branch and also ensure that
        // hashing an empty slice isn't a no-op, which is good for hashing structs containing
        // multiple slices.

        let mut padded_chunk = [0; USIZE_BYTES];

        let mut byte_offset = 0; // For reading partial_chunk and writing padded_chunk.

        // This code below compiles to a really small branch-free way of padding the parital_chunk.

        // All powers of two less than or equal to USIZE_BYTES.
        #[cfg(target_pointer_width = "64")]
        let partial_steps = [4, 2, 1];
        #[cfg(target_pointer_width = "32")]
        let partial_steps = [2, 1];

        for &step in &partial_steps {
            unsafe {
                // See inline comments below for safety

                // `byte_offset` is always smaller than the sum (or bit-or, but that's the same for
                // distinct powers of two) of all `step` values processed so far. Since all step
                // values sum to `USIZE_BYTES-1`, `byte_offset + step < USIZE_BYTES` and hence
                // `byte_offset..byte_offset + step` is in bounds for `padded_chunk`.
                let dst_ptr = padded_chunk.as_mut_ptr().add(byte_offset);
                // This copy may and will overlap, so don't use `ptr::copy_nonoverlapping` here
                ptr::copy(
                    if partial_chunk.len() & step != 0 {
                        // We also only add steps two `byte_offset` whose corresponding bit is set
                        // in `partial_chunk.len()`, this ensures that `byte_offset <=
                        // partial_chunk.len()` always holds. At this point we haven't added `step`
                        // to byte_offset yet, but the `if` tells us that we will below, so we know
                        // `byte_offset + step <= partial_chunk.len()` and thus
                        // `byte_offset..byte_offset + step` is in bounds for `partial_chunk`.
                        partial_chunk.as_ptr().add(byte_offset)
                    } else {
                        // In this case the data would be out of bounds for partial_chunk, so we use
                        // our dst pointer to turn this into a no-op. This trick allows this `if` to
                        // be performed as a selection of two pointers, which often will be compiled
                        // to code that doesn't branch.
                        dst_ptr
                    },
                    dst_ptr,
                    // See above for why `step` bytes pointed to by src and dst pointer are in
                    // bounds.
                    step,
                );
            }
            // This ensures that a) `read_offset` is advanced by step if we copied step bytes,
            // b) `read_offset < USIZE_BYTES` and c) `read_offset <= partial_chunk.len()`.
            byte_offset |= step & partial_chunk.len();
        }

        copy.write_usize(usize::from_ne_bytes(padded_chunk));

        self.state = copy.state;
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.write_usize(i as usize);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.write_usize(i as usize);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.write_usize(i as usize);
    }

    #[cfg(target_pointer_width = "64")]
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.write_usize(i as usize);
    }

    #[cfg(target_pointer_width = "32")]
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.write_usize(i as usize);
        self.write_usize((i >> 32) as usize);
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.write_u64(i as u64);
        self.write_u64((i >> 64) as u64);
    }

    #[inline]
    fn write_i8(&mut self, i: i8) {
        self.write_u8(i as u8);
    }

    #[inline]
    fn write_i16(&mut self, i: i16) {
        self.write_u16(i as u16);
    }

    #[inline]
    fn write_i32(&mut self, i: i32) {
        self.write_u32(i as u32);
    }

    #[inline]
    fn write_i64(&mut self, i: i64) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_i128(&mut self, i: i128) {
        self.write_u128(i as u128);
    }

    #[inline]
    fn write_isize(&mut self, i: isize) {
        self.write_usize(i as usize);
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::{prelude::v1::*, println};

    fn hash_usize(value: usize) -> usize {
        let mut hasher = ZwoHasher::default();
        hasher.write_usize(value);
        hasher.finish() as usize
    }

    /// Make sure that for every consecutive 8 bits of the input, over all possible values of those
    /// 8 bits (with the others set to zero), and every consecutive 1 bits of the output, there are
    /// almost no collisions.
    ///
    /// This is a desirable property, especially for consecutive low and high output bits, as these
    /// are used as indices or as filter in hashtables. E.g. the stdlibs hashbrown hash tables takes
    /// a variable number of lower bits as index and use the upper 8 bits to pre-filter entries with
    /// colliding indices.
    #[test]
    fn usize_byte_subbword_collision_rate() {
        let mut histogram = [0; 257];

        for i in 0..USIZE_BITS - 8 {
            for j in 0..USIZE_BITS - 16 {
                let mut hash_subbytes: Vec<_> =
                    (0..256).map(|b| (hash_usize(b << i) >> j) as u16).collect();
                hash_subbytes.sort();
                hash_subbytes.dedup();
                histogram[hash_subbytes.len()] += 1;
            }
        }

        for (len, &count) in histogram.iter().enumerate() {
            if count > 0 {
                println!("{}: {}", len, count);
            }
        }

        for (len, &count) in histogram.iter().enumerate() {
            // We allow up to one collision
            assert!(len >= 255 || count == 0);
        }
    }
}
