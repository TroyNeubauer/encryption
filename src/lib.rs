#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(feature = "std"), no_std)]
//! 
//!
//! ```
//! use encryption::{Key, alg1::{CipherBlock, Algorithm1}};
//! use rand::{RngCore, SeedableRng};
//!
//! // Use a more secure seeding algorithm!
//! let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEADBEEF);
//!
//! // Encryption is done in place so this is where the plaintext goes
//! let mut block_bytes = [0u8; 28];
//! rng.fill_bytes(&mut block_bytes);
//! let original_block = Clone::clone(&block_bytes);
//!
//! // Generate our encryption key
//! let mut key_bytes = [0u8; 64];
//! rng.fill_bytes(&mut key_bytes);
//! let key = Key::new(key_bytes);
//!
//! // We also need an index key that is used to encrypt the index when sent in the clear
//! let mut index_key = [0u8; 4];
//! rng.fill_bytes(&mut index_key);
//! let index_key = u32::from_ne_bytes(index_key);
//!
//! // Create our block and cipher
//! let mut block = CipherBlock::new(block_bytes);
//! let cipher = Algorithm1::new(&key, index_key);
//!
//! // Each message block is encrypted with a different index that determines which part of the key
//! // is Xored with the plaintext. This should change for every message. Incrementing is fine
//! let index = 16460;
//! cipher.cipher_block(index, &mut block);
//! cipher.cipher_block(index, &mut block);
//! assert_eq!(block.as_ref(), original_block.as_ref());
//! ```

mod key;
pub use key::{Key, Word, KEY};

mod algorithm;
pub use algorithm::{GenericCipher, GenericCipherBlock, Index};

pub mod alg1;
pub mod alg2;
