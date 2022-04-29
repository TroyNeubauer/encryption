//! Algorithm fon encrypting 248 byte blocks with 64 bit indices, hashed by passing each byte in
//! the index through the AES S-BOX

const S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

use core::mem::size_of;

use crate::{GenericCipher, GenericCipherBlock, Key};

const BLOCK_SIZE: usize = 248;
const ELEMENT_COUNT: usize = 31;

pub type CipherBlock = GenericCipherBlock<BLOCK_SIZE>;

/// Passes each byte of `index` through the AES S-Box to provide a non linear hash
fn hash(index: u64) -> u64 {
    let bytes = index.to_ne_bytes().map(|b| S_BOX[b as usize]);
    u64::from_ne_bytes(bytes)
}

pub struct Algorithm2<'k, const KEY_SIZE: usize>(
    GenericCipher<'k, fn(u64) -> u64, u64, KEY_SIZE, BLOCK_SIZE>,
);

impl<'k, const KEY_BYTES: usize> Algorithm2<'k, KEY_BYTES> {
    pub fn new(key: &'k Key<KEY_BYTES>, index_key: u64) -> Self {
        Self(GenericCipher::new(hash, key, index_key))
    }

    /// Encrypts or decrypts a single block using `key` and `index`.
    /// Because Xor is used, the encryption and decryption operation is the same
    pub fn cipher_block(&self, index: u64, block: &mut GenericCipherBlock<BLOCK_SIZE>) {
        self.0.cipher_block::<31, 8, u64>(index, block.into())
    }
}

/// High level index block for storing index and encrypted data togther, optimized for 32 bytes
/// messages
#[repr(C, align(8))]
#[derive(Default)]
pub struct IndexedBlock {
    index: u64,
    data: [u64; ELEMENT_COUNT],
}

impl IndexedBlock {
    pub fn new() -> Self {
        Self {
            index: 0,
            data: [0; ELEMENT_COUNT],
        }
    }

    pub fn data(&self) -> &[u64; ELEMENT_COUNT] {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut [u64; ELEMENT_COUNT] {
        &mut self.data
    }

    pub fn index(&mut self) -> u64 {
        self.index
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

    pub fn do_cipher<Hash, const KEY_SIZE: usize>(&mut self, cipher: &Algorithm2<'_, KEY_SIZE>) {
        let data: &mut [u64; ELEMENT_COUNT] = &mut self.data;

        //SAFETY:
        // 1. size_of([u32; 7]) is 28 so we are transmuting to a pointer with the same length
        // 2. u8 can have any alignment
        // 3. The last readable index is in range of the same allocated object by the math above
        let data: &mut [u8; BLOCK_SIZE] = unsafe { core::mem::transmute(data) };
        let block = crate::algorithm::CipherBlockRef::new(data);
        cipher
            .0
            .cipher_block::<ELEMENT_COUNT, 8, u64>(self.index, block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn encrypt_and_decrypt_basic() {
        let mut i = 0;
        for _ in 0..100 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(i);

            let mut block_bytes = [0u8; 248];
            rng.fill_bytes(&mut block_bytes);
            let original_block = Clone::clone(&block_bytes);

            let mut key_bytes = [0u8; 2048];
            rng.fill_bytes(&mut key_bytes);
            let key = Key::new(key_bytes);

            let mut index_key = [0u8; 8];
            rng.fill_bytes(&mut index_key);
            let index_key = u64::from_ne_bytes(index_key);

            let mut block = CipherBlock::new(block_bytes);
            let cipher = Algorithm2::new(&key, index_key);

            for _ in 0..100 {
                let index = i;
                cipher.cipher_block(index, &mut block);
                cipher.cipher_block(index, &mut block);
                assert_eq!(block.as_ref(), original_block.as_ref());
                i += 1;
            }
        }

        crate::key::print_freq();
    }

    #[test]
    fn index_block() {
        use core::mem::{align_of, size_of};
        assert_eq!(size_of::<IndexedBlock>(), 256);
        assert_eq!(align_of::<IndexedBlock>(), 8);
    }
}
