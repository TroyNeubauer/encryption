use core::mem::size_of;
#[cfg(feature = "std")]
use lazy_static::lazy_static;
#[cfg(feature = "std")]
use std::{collections::HashMap, sync::Mutex};

/// A type that is safe to use as a word in a block or key
///
/// # Safety
/// 1. All bit patterns of implementing types must be valid
/// 2. Implementing types must require the alignment of `Self` to be less than or equal to 8 bytes
pub unsafe trait Word: Copy + From<u8> {}

/// Represents an `N` element key of type `W`.
/// Used so that larger element sizes such as u32 or u64 can be used, increasing effiency over u8
#[repr(align(8))]
pub struct Key<const N: usize>([u8; N]);

/// The symmetric key used for both encryption and decryption
pub const KEY: Key<53280> = Key::new(*include_bytes!("../private/key.bin"));

#[cfg(feature = "std")]
lazy_static! {
    static ref FREQ: Mutex<HashMap<usize, usize>> = Mutex::new(HashMap::new());
}

#[cfg(test)]
pub fn print_freq() {
    let lock = FREQ.lock().unwrap();
    for (k, v) in lock.iter() {
        println!("{}: {}", k, v);
    }
}

impl<const N: usize> Key<N> {
    /// Creates a new key by copying the data from `key` into self
    ///
    /// # Panics
    ///
    /// If `key.len()` is not a multiple of `size_of::<T>()`
    pub const fn new(key: [u8; N]) -> Self {
        Self(key)
    }

    /// Returns a slice len `key_len` of this key based on word offset module the key length
    /// `L` is the number of elements returned
    pub fn subkey<W: Word, const L: usize>(&self, word_offset: usize) -> &[W; L] {
        let key_elements = N / size_of::<W>();
        if L > key_elements {
            panic!(
                "Subkey larger than main key! Main key bytes: {}, requested bytes: {} ({} elements)",
                N, L * size_of::<W>(), L
            );
        }

        // We need to find `L` contiguous elements, so the maximum index (exclusive) is `L`
        // less than the total length of the key
        let max_index = (key_elements + 1) - L;

        // Ensure offset is in range
        let offset = word_offset % max_index;

        // SAFETY:
        // `W` is only imelemented for types with an alignment of 8 bytes or less, and becasue Self
        // is aligned to 8 byte bounderies via #[reper(align(8))], the resulting pointer is aligned
        let ptr: *const W = self.0.as_ptr() as *const W;

        #[cfg(feature = "std")]
        {
            let mut lock = FREQ.lock().unwrap();
            let count = lock.entry(offset).or_insert_with(|| 0);
            *count += 1;
        }

        // SAFETY:
        // 1. Offset is in range by the calculation of `max_index` above
        // 2. At least `L` elements are readable by the `max_index` calculation
        // 3. The result is aligned because `ptr` is aligned
        // 4. The lifetime of the result is 'k because `self` is 'k
        let subkey_start = unsafe { ptr.add(offset) };

        // SAFETY:
        // 1. The layout of a array type ([T; N]) has the same alignment requirements of T, and has
        //    the size of size_of::<T>() * N
        // 2. The lifetime of `self.0` is 'self, so the lifetime elision knows that the returned
        //    lifetime is 'self
        //
        // See: https://doc.rust-lang.org/reference/type-layout.html#array-layout
        unsafe { &*(subkey_start as *const [W; L]) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_len() {
        // 53280 is a special number.
        // It is equal to `2^15*(1+5/8)+32`
        // We want this so that when the optimizer looks at the calculation of `max_index` in `subkey`,
        // it sees that its value is `2^15*(1+5/8)` which should reduce the modulus to bitwise
        // instructions (please compiler)
        assert_eq!(KEY.0.len(), 53280);
        assert_eq!(KEY.0.len() - 32, 2usize.pow(15) * 13 / 8);
    }

    #[test]
    fn subkey() {
        const KEY_LEN: usize = 32;
        let key: [u8; KEY_LEN] = (0u8..KEY_LEN as u8)
            .into_iter()
            .collect::<Vec<_>>()
            .as_slice()
            .try_into()
            .unwrap();

        let key = Key::new(key);
        for i in 0..32 {
            let subkey = key.subkey::<u32, 1>(i);
            let b = (i * 4 % KEY_LEN) as u8;
            let expected = [b, b + 1, b + 2, b + 3];
            assert_eq!(subkey[0], u32::from_ne_bytes(expected));
        }

        for i in 0..32 {
            let subkey = key.subkey::<u32, 4>(i);
            // The numbers are a bit strange here because when getting a 16 byte subkey from a 32
            // byte key, there are only 5 positions we can go to to get a unique key. We always
            // check the last 32 bit word of the subkey, so we need to add 12 because 3 * 4. We do
            // mod 20 because of 5 possible alignments we can have, 5 * 4 == 12
            let b = (i * 4 % 20) as u8 + 12;
            let expected = [b, b + 1, b + 2, b + 3];
            assert_eq!(subkey[3], u32::from_ne_bytes(expected));
        }
        //Make sure this works for zero sized types
        let zst = key.subkey::<u32, 0>(0);
        assert!(zst.is_empty());
    }
}

/// SAFETY: u8 has no invalid bit patterns
unsafe impl Word for u8 {}
/// SAFETY: u16 has no invalid bit patterns
unsafe impl Word for u16 {}
/// SAFETY: u32 has no invalid bit patterns
unsafe impl Word for u32 {}
