use crate::key::Key;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ops::Deref;

pub trait Index: core::ops::BitXor<Output = Self> + Sized + Copy {
    fn to_usize(self) -> usize;
}

#[repr(C, align(8))]
pub struct GenericCipherBlock<const N: usize>(pub [u8; N]);

/// A reference to a cipher block that has an alignemnt of `A`
pub struct CipherBlockRef<'a, const N: usize, const A: usize>(&'a mut [u8; N]);

impl<'a, const N: usize, const A: usize> CipherBlockRef<'a, N, A> {
    pub fn new(buf: &'a mut [u8; N]) -> Self {
        assert_eq!(
            buf.as_ptr() as usize % A,
            0,
            "CipherBlockRefs must be aligned to at least {} byte bounderies",
            A
        );
        Self(buf)
    }
}

pub struct GenericCipher<'k, Hash, IndexTy, const KEY_BYTES: usize, const BLOCK_BYTES: usize>
where
    Hash: Fn(IndexTy) -> IndexTy,
    IndexTy: Index,
{
    hash: Hash,
    key: &'k Key<KEY_BYTES>,
    index_key: IndexTy,
    _index: PhantomData<IndexTy>,
}

impl<'k, Hash, IndexTy, const KEY_BYTES: usize, const BLOCK_BYTES: usize>
    GenericCipher<'k, Hash, IndexTy, KEY_BYTES, BLOCK_BYTES>
where
    Hash: Fn(IndexTy) -> IndexTy,
    IndexTy: Index,
{
    pub fn new(hash: Hash, key: &'k Key<KEY_BYTES>, index_key: IndexTy) -> Self {
        Self {
            hash,
            key,
            index_key,
            _index: PhantomData,
        }
    }

    /// Performs encryption or decryption of a single block.
    /// `L` determines many elements the subkey has with word size `W`. Because N is in bytes, `L` should always
    /// be set to N / `size_of::<W>()`.
    ///
    /// Returns Err on error, and the bytes of `block` are not guaranteed to be encrypted or
    /// decrypted
    /// If Ok(()) is returned, all bytes of `block` have been encrypted/decrypted
    ///
    /// # Panics
    /// This function panics if L is the wrong size.
    /// If L is the correct size for N. This function will never panic, otherwise it will always
    /// panic
    pub fn cipher_block<const L: usize, const A: usize, W: crate::Word>(
        &self,
        index: IndexTy,
        block: CipherBlockRef<BLOCK_BYTES, A>,
    ) {
        //TODO: Calculate `L` automaticaly once const generic parameters can be set to const functions
        if BLOCK_BYTES / size_of::<W>() != L {
            // User choose wrong L for N
            panic!(
                "Wrong L ({}), for block bytes {}. Expected L to be {}",
                L,
                BLOCK_BYTES,
                BLOCK_BYTES / size_of::<W>()
            );
        }
        // The word size we picked has the alignment of at least A
        assert!(align_of::<W>() >= A);

        // Perform Xor first, so that an attacker doesn't know the inputs to the hash function
        let index = index ^ self.index_key;
        let index = (self.hash)(index);
        let index = index.to_usize();

        #[cfg(feature = "word_xor")]
        {
            let key = self.key.subkey::<W, L>(index);

            // SAFETY: u8 is safe to transmute to `Word`. There are no invalid bit patterns by the impl
            // constraints of Word (unsafe trait)
            let (before, buf, after) = unsafe { block.0.align_to_mut::<W>() };

            // These lengths are guaranteed to be 0 because `CipherBlockRef` always has `A` byte
            // alignment, which is at least at least as large as `W`'s alignment
            debug_assert!(before.is_empty());
            debug_assert!(after.is_empty());
            // Perform Xor encryption
            for i in 0..buf.len() {
                buf[i] ^= key[i];
            }
        }
        #[cfg(not(feature = "word_xor"))]
        {
            let key = self.key.as_words::<W>();

            // SAFETY: u8 is safe to transmute to `Word`. There are no invalid bit patterns by the impl
            // constraints of Word (unsafe trait)
            let (before, buf, after) = unsafe { block.0.align_to_mut::<W>() };

            // These lengths are guaranteed to be 0 because `CipherBlockRef` always has `A` byte
            // alignment, which is at least at least as large as `W`'s alignment
            debug_assert!(before.is_empty());
            debug_assert!(after.is_empty());

            // The index of one past the last element we can access
            let max_element = key.len() - buf.len();
            let word_bits = size_of::<W>() * 8;
            let max_bit = max_element * word_bits;

            // Because of the bit offsets, we may need to strattle two extra words, so subtract the
            // number of bytes in a word when finding offset
            let offset = index % max_bit;
            let mut word_offset = offset / word_bits;
            let bit_offset = offset % word_bits;
            //start encrypting the high bits of block starting with the key bit at `bit_offset`

            dbg!(
                key.len(),
                buf.len(),
                max_element,
                max_bit,
                offset,
                index,
                word_offset,
                bit_offset
            );

            //encrypts the upper part of `block`
            let encrypt_upper = |block_word: &mut W, key_word: W| {
                // low bits of key are zero after bit shifting, so we can simply xor the whole thing
                dbg!(bit_offset);
                let key = key_word << bit_offset;
                *block_word ^= key;
            };

            //encrypts the lower part of `block`
            let encrypt_lower = |block_word: &mut W, key_word: W| {
                // high bits of key are zero after bit shifting, so we can simply xor the whole thing
                dbg!(bit_offset);
                let key = key_word >> bit_offset;
                *block_word ^= key;
            };
            if buf.len() == 0 || key.len() == 0 {
                return;
            }
            //encrypt upper part from first key word

            let buf_len = buf.len();
            let key_word = key[word_offset];
            let mut block_word = &mut buf[0];
            encrypt_upper(block_word, key_word);

            // we have to encrypt the first and last word bits seperately to handle bit alignment,
            // so run for one less iteration
            for i in 0..buf_len - 1 {
                let key_word = key[word_offset];
                word_offset += 1;
                dbg!(word_offset, i, key_word);
                encrypt_lower(block_word, key_word);
                block_word = &mut buf[i + 1];
                encrypt_upper(block_word, key_word);
            }
            let key_word = key[word_offset + 1];
            encrypt_lower(block_word, key_word);
        }
    }
}

impl Index for u32 {
    fn to_usize(self) -> usize {
        self.try_into().unwrap()
    }
}

impl Index for u64 {
    fn to_usize(self) -> usize {
        self.try_into().unwrap()
    }
}

impl<const N: usize> GenericCipherBlock<N> {
    pub fn new(buf: [u8; N]) -> Self {
        Self(buf)
    }
}

impl<'a, const N: usize, const A: usize> From<&'a mut GenericCipherBlock<N>>
    for CipherBlockRef<'a, N, A>
{
    fn from(t: &'a mut GenericCipherBlock<N>) -> Self {
        Self(&mut t.0)
    }
}

impl<const N: usize> Deref for GenericCipherBlock<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8]> for GenericCipherBlock<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
