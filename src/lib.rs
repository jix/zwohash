//! A fast non-randomized hash function.
//!
//! Not hardened against DOS attacks, thus be careful when using this with user-controlled keys.
//! Optimized for small integer keys, but handles other non-adversarial use cases.
#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(any(feature = "std"))]
use core::hash::BuildHasherDefault;
use core::{hash::Hasher, ptr::copy_nonoverlapping};

#[cfg(any(feature = "std"))]
use std::collections;

/// A [`collections::HashMap`] using [`ZwoHasher`] to compute hashes.
#[cfg(all(feature = "std"))]
pub type HashMap<K, V> = collections::HashMap<K, V, BuildHasherDefault<ZwoHasher>>;
/// A [`collections::HashSet`] using [`ZwoHasher`] to compute hashes.
#[cfg(all(feature = "std"))]
pub type HashSet<V> = collections::HashSet<V, BuildHasherDefault<ZwoHasher>>;

/// A fast non-randomized hash function.
///
/// Not hardened against DOS attacks, thus be careful when using this with user-controlled keys.
/// Optimized for small integer keys, but handles other non-adversarial use cases.
///
/// Like rustc's FxHash the output fits in an usize. On 32-bit targets the higher bits of the result
/// are zeros.
pub struct ZwoHasher {
    state: usize,
}

impl Default for ZwoHasher {
    #[inline]
    fn default() -> ZwoHasher {
        ZwoHasher { state: 0 }
    }
}

const BYTES: usize = core::mem::size_of::<usize>();

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
        // This is a bit ugly, but that way it doesn't contain any redundant range checks and gets
        // nicely optimized when inlined with a known `bytes.len()`.
        unsafe {
            // This is safe because any pointer add and any copy_nonoverlapping is guarded by a
            // preceeding manual range check. The copy is guaranteed to be nonoverlaping as the
            // source points to a slice passed to us and the destination is in our local stack
            // frame.

            let mut copy = ZwoHasher { state: self.state };

            let mut full_chunk = [0u8; BYTES];

            let bytes_base = bytes.as_ptr();
            let mut pos = 0;

            while pos + BYTES <= bytes.len() {
                copy_nonoverlapping(bytes_base.add(pos), full_chunk.as_mut_ptr(), BYTES);

                copy.write_usize(usize::from_ne_bytes(full_chunk));
                pos += BYTES;
            }

            // If we have less than BYTES trailing bytes, we fill up partial_chunk with them and
            // then process that. We pad with nonzero bytes, so we don't produce collisions for
            // slices that have the same prefix and are zero padded.
            let mut partial_chunk = M.to_ne_bytes();

            match bytes.len() - pos {
                #[cfg(target_pointer_width = "64")]
                7 => copy_nonoverlapping(bytes_base.add(pos), partial_chunk.as_mut_ptr(), 7),
                #[cfg(target_pointer_width = "64")]
                6 => copy_nonoverlapping(bytes_base.add(pos), partial_chunk.as_mut_ptr(), 6),
                #[cfg(target_pointer_width = "64")]
                5 => copy_nonoverlapping(bytes_base.add(pos), partial_chunk.as_mut_ptr(), 5),
                #[cfg(target_pointer_width = "64")]
                4 => copy_nonoverlapping(bytes_base.add(pos), partial_chunk.as_mut_ptr(), 4),
                // the cases below this line can happen for 32-bit targets
                3 => copy_nonoverlapping(bytes_base.add(pos), partial_chunk.as_mut_ptr(), 3),
                2 => copy_nonoverlapping(bytes_base.add(pos), partial_chunk.as_mut_ptr(), 2),
                1 => copy_nonoverlapping(bytes_base.add(pos), partial_chunk.as_mut_ptr(), 1),
                // we also perform one extra write_usize for a slice with multiple of 8 len
                // (including the empty slice) as a slice terminator.
                0 => (),
                // we only get to this "loop" if pos + BYTES > bytes.len() and we cover all
                // BYTES cases above
                _ => core::hint::unreachable_unchecked(),
            }

            copy.write_usize(usize::from_ne_bytes(partial_chunk));

            self.state = copy.state;
        }
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

#[cfg(test)]
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
