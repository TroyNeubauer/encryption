use crate::key::Key;
use core::marker::PhantomData;
use core::mem::size_of;
use core::ops::Deref;

pub trait Index: core::ops::BitXor<Output = Self> + Sized + Copy {
    fn to_usize(self) -> usize;
}

#[repr(C, align(4))]
pub struct GenericCipherBlock<const N: usize>(pub [u8; N]);

/// A reference to a cipher block that has at least 4 byte alignment
pub struct CipherBlockRef<'a, const N: usize>(&'a mut [u8; N]);

impl<'a, const N: usize> CipherBlockRef<'a, N> {
    pub fn new(buf: &'a mut [u8; N]) -> Self {
        assert_eq!(buf.as_ptr() as usize % 4, 0, "CipherBlockRefs must be aligned to at least 4 byte bounderies");
        Self(buf)
    }
}

pub struct GenericCipher<'k, Hash, IndexTy, const KEY_BYTES: usize, const BLOCK_BYTES: usize>
where
    Hash: Fn(IndexTy) -> IndexTy,
    IndexTy: Index,
{
    //hash: Hash,
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
    /// `L` determines many elements the u32 subkey has. Because N is in bytes, `L` should always
    /// be set to N / 4.
    ///
    /// Returns Err on error, and the bytes of `block` are not guaranteed to be encrypted or
    /// decrypted
    /// If Ok(()) is returned, all bytes of `block` have been encrypted/decrypted
    ///
    /// # Panics
    /// This function panics if L is the wrong size.
    /// If L is the correct size for N. This function will never panic, otherwise it will always
    /// panic
    pub fn cipher_block<const L: usize>(
        &self,
        index: IndexTy,
        block: CipherBlockRef<BLOCK_BYTES>,
    ) {
        if BLOCK_BYTES / size_of::<u32>() != L {
            // User choose wrong L for N
            panic!(
                "Wrong L ({}), for block bytes {}. Expected L to be {}",
                L,
                BLOCK_BYTES,
                BLOCK_BYTES / size_of::<u32>()
            );
        }

        // Perform Xor first, so that an attacker doesn't know the inputs to the hash function
        let index = index ^ self.index_key;
        let index = (self.hash)(index);
        let index = index.to_usize();

        let key = self.key.subkey::<u32, L>(index);

        // SAFETY: u8 is safe to transmute to u32. There are no invalid bit patterns
        let (before, buf, after) = unsafe { block.0.align_to_mut::<u32>() };

        // These lengths are guaranteed to be 0 because `CipherBlockRef` always has 4 byte alignment
        debug_assert!(before.is_empty());
        debug_assert!(after.is_empty());
        // Perform Xor encryption
        for i in 0..buf.len() {
            buf[i] ^= key[i];
        }
    }
}

impl Index for u32 {
    fn to_usize(self) -> usize {
        assert!(
            size_of::<usize>() >= size_of::<u32>(),
            "8 and 16 bit targets not supported yet!"
        );
        self.try_into().unwrap()
    }
}

impl<const N: usize> GenericCipherBlock<N> {
    pub fn new(buf: [u8; N]) -> Self {
        Self(buf)
    }
}

impl<'a, const N: usize> From<&'a mut GenericCipherBlock<N>> for CipherBlockRef<'a, N> {
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


