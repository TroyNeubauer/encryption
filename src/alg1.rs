use core::mem::size_of;

use crate::{GenericCipher, GenericCipherBlock, Key};

pub type CipherBlock = GenericCipherBlock<28>;

fn identity_hash(index: u32) -> u32 {
    index
}

pub struct MainCipher<'k, Hash, const KEY_SIZE: usize>(GenericCipher<'k, Hash, u32, KEY_SIZE, 28>)
where
    Hash: Fn(u32) -> u32;

impl<'k, const KEY_BYTES: usize> MainCipher<'k, fn(u32) -> u32, KEY_BYTES> {
    pub fn new(key: &'k Key<KEY_BYTES>, index_key: u32) -> Self {
        Self(GenericCipher::new(identity_hash, key, index_key))
    }

    /// Encrypts or decrypts a single block using `key` and `index`.
    /// Because Xor is used, the encryption and decryption operation is the same
    pub fn cipher_block(&self, index: u32, block: &mut GenericCipherBlock<28>) {
        self.0.cipher_block::<7>(index, block.into())
    }
}

/// High level index block for storing index and encrypted data togther, optimized for 32 bytes
/// messages
#[repr(C)]
#[derive(Default)]
pub struct IndexedBlock {
    tag: Tag31_1,
    data: [u32; 7],
}

impl IndexedBlock {
    pub fn new() -> Self {
        Self {
            tag: Tag31_1::new(0),
            data: [0; 7],
        }
    }

    pub fn data(&self) -> &[u32; 7] {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut [u32; 7] {
        &mut self.data
    }

    pub fn tag(&mut self) -> &mut Tag31_1 {
        &mut self.tag
    }

    /// Returns this entire message as a byte slice, sutiable for transmitting
    pub fn as_bytes(&self) -> &[u8] {
        let this: *const Self = self;
        let ptr: *const u8 = this as *const u8;
        unsafe { core::slice::from_raw_parts(ptr, size_of::<Self>()) }
    }

    /// Returns this entire message as a byte slice, sutiable for reciving
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        let this: *mut Self = self;
        let ptr: *mut u8 = this as *mut u8;
        unsafe { core::slice::from_raw_parts_mut(ptr, size_of::<Self>()) }
    }

    pub fn do_cipher<Hash, const KEY_SIZE: usize>(&mut self, cipher: &MainCipher<'_, Hash, KEY_SIZE>) where
        Hash: Fn(u32) -> u32
    {
        let index = Tag::get_index(self.tag());
        let data: &mut [u32; 7] = &mut self.data;

        //SAFETY:
        // 1. size_of([u32; 7]) is 28 so we are transmuting to a pointer with the same length
        // 2. u8 can have any alignment
        // 3. The last readable index is in range of the same allocated object by the math above
        let data: &mut [u8; 28] = unsafe { core::mem::transmute(data) };
        let block = crate::algorithm::CipherBlockRef::new(data);
        cipher.0.cipher_block::<7>(index, block)
    }
}

/// Represents the header bits of a message that contain the index and other user specified data
pub trait Tag {
    type IndexTy: crate::Index;

    /// Creates a new Tag. The intex bits will be initally set to zero
    fn new(index: Self::IndexTy) -> Self;

    /// Returns the index of this tag with the tag part removed
    fn get_index(&self) -> Self::IndexTy;

    fn set_index(&mut self, index: Self::IndexTy);

    /// Returns the tag bits
    fn get_tag(&self) -> usize;

    /// Sets the tag bits stored in this tag
    /// Only the lowest [`tag_bits_count`] bits will be stored and be available with [`get_tag`]
    /// the higher bits will be discarded
    fn set_tag(&mut self, tag: usize);

    /// Returns the number of tag bits this tag supports
    fn tag_bits_count() -> usize;
}

const INDEX_MASK_31: u32 = 0x7FFF_FFFF;
const TAG_31_BITS_OFFSET: u32 = 31;

#[derive(Default)]
pub struct Tag31_1(u32);

impl Tag for Tag31_1 {
    type IndexTy = u32;

    fn new(index: Self::IndexTy) -> Self {
        Tag31_1(index)
    }

    fn get_index(&self) -> Self::IndexTy {
        self.0 & INDEX_MASK_31
    }

    fn set_index(&mut self, index: Self::IndexTy) {
        self.0 = (index & INDEX_MASK_31) | (self.0 & !INDEX_MASK_31);
    }

    fn get_tag(&self) -> usize {
        ((self.0 & !INDEX_MASK_31) >> TAG_31_BITS_OFFSET) as usize
    }

    fn set_tag(&mut self, tag: usize) {
        self.0 = (self.0 & INDEX_MASK_31) | (tag << TAG_31_BITS_OFFSET) as u32
    }

    fn tag_bits_count() -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn encrypt_and_decrypt_basic() {
        for i in 0..10 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(i);

            let mut block_bytes = [0u8; 28];
            rng.fill_bytes(&mut block_bytes);
            let original_block = Clone::clone(&block_bytes);

            let mut key_bytes = [0u8; 64];
            rng.fill_bytes(&mut key_bytes);
            let key = Key::new(key_bytes);

            let mut index_key = [0u8; 4];
            rng.fill_bytes(&mut index_key);
            let index_key = u32::from_ne_bytes(index_key);

            let mut block = CipherBlock::new(block_bytes);
            let cipher = MainCipher::new(&key, index_key);

            //let index = rng.gen();
            let index = i as u32;
            cipher.cipher_block(index, &mut block);
            cipher.cipher_block(index, &mut block);
            assert_eq!(block.as_ref(), original_block.as_ref());
        }

        crate::key::print_freq();
    }

    #[test]
    fn encrypt_and_decrypt() {

        let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEADBEEF);
        let mut index_key = [0u8; 4];
        rng.fill_bytes(&mut index_key);
        let index_key = u32::from_ne_bytes(index_key);

        let mut key_bytes = [0u8; 64];
        rng.fill_bytes(&mut key_bytes);
        let key = Key::new(key_bytes);
        let cipher = MainCipher::new(&key, index_key);

        for i in 0..10 {

            let mut block = IndexedBlock::new();
            rng.fill_bytes(block.as_bytes_mut());
            block.tag().set_index(i as u32);
            block.tag().set_tag(0);
            let original_block = block.data().to_vec(); 

            block.do_cipher(&cipher);
            block.do_cipher(&cipher);
            assert_eq!(&original_block, block.data().as_slice());
        }

        crate::key::print_freq();
    }

    #[test]
    fn tag() {
        let mut tag: Tag31_1 = Tag::new(0);
        assert_eq!(Tag31_1::tag_bits_count(), 1);
        assert_eq!(tag.get_index(), 0);
        assert_eq!(tag.get_tag(), 0);

        tag.set_tag(1);
        assert_eq!(tag.get_tag(), 1);

        tag.set_tag(0);
        assert_eq!(tag.get_tag(), 0);

        tag.set_tag(3);
        assert_eq!(tag.get_tag(), 1);

        tag.set_index(0xFFFF_FFFF);
        assert_eq!(tag.get_index(), INDEX_MASK_31);
        assert_eq!(tag.get_tag(), 1);

        tag.set_index(0);
        assert_eq!(tag.get_index(), 0);
        assert_eq!(tag.get_tag(), 1);
    }

    #[test]
    fn index_block() {
        use core::mem::{align_of, size_of};
        // This must be 32 bytes to enforce our message length
        assert_eq!(size_of::<IndexedBlock>(), 32);
        assert_eq!(align_of::<IndexedBlock>(), 4);
    }
}
