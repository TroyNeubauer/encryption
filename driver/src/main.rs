use rand::{Rng, RngCore};
use std::io::BufRead;

fn read_hex_bytes<const N: usize>(msg: &str, rng: &mut impl Rng) -> [u8; N] {
    println!("Enter {N} byte hex {msg}, or enter for random key");
    let mut buf = [0u8; N];
    let mut line = String::new();
    let mut bytes_vec = vec![];
    loop {
        if !line.is_empty() {
            //Second time in loop
            println!("{} bytes remaining", N - bytes_vec.len());
        }
        line.clear();
        std::io::stdin().read_line(&mut line).unwrap();
        let mut line = line.trim();
        if line.starts_with("0x") {
            line = &line[2..];
        }
        if line.is_empty() {
            rng.fill_bytes(&mut buf);
            println!("  filling with random bytes");
            println!("  {} is: 0x{}", msg, hex::encode(buf));
            break;
        } else {
            match hex::decode(&line) {
                Ok(bytes) => {
                    bytes_vec.extend(bytes);
                    if bytes_vec.len() >= N {
                        buf.copy_from_slice(&bytes_vec[..N]);
                        break;
                    }
                }
                Err(e) => {
                    println!("Only hex digits can be supplied! {e:?}");
                }
            }
        }
    }
    buf
}

fn read_line<const N: usize>(msg: &str) -> [u8; N] {
    println!("Enter {N} byte {msg}, ASCII characters are supported, or hex literals, optionally starting with 0x");
    let mut buf = [0u8; N];
    let mut line = String::new();
    let mut bytes_vec = vec![];
    loop {
        if !line.is_empty() {
            //Second time in loop
            println!("{} bytes remaining", N - bytes_vec.len());
        }
        line.clear();
        std::io::stdin().read_line(&mut line).unwrap();
        let line = line.trim();
        if let Ok(decoded_hex) = hex::decode(line) {
            if decoded_hex.len() == N {
                println!("  assuming hex encoding");
                buf.copy_from_slice(&decoded_hex);
                break;
            }
        }
        //check for 0x
        if let Ok(decoded_hex) = hex::decode(&line[2..]) {
            if decoded_hex.len() == N && &line[..2] == "0x" {
                println!("  assuming hex encoding");
                buf.copy_from_slice(&decoded_hex);
                break;
            }
        }

        bytes_vec.extend(line.trim().bytes());
        if bytes_vec.len() >= N {
            buf.copy_from_slice(&bytes_vec[..N]);
            break;
        }
    }
    buf
}

fn main() {
    let mut rng = rand::rngs::OsRng;
    //Assert cryptographically secure
    let _: &dyn rand::CryptoRng = &rng;

    let main_key: [u8; 128] = read_hex_bytes("main key", &mut rng);
    let index_key: [u8; 4] = read_hex_bytes("index key", &mut rng);
    let plaintext: [u8; 28] = read_line("plaintext");
    println!(
        "Encrypting: {}, 0x{}",
        String::from_utf8_lossy(&plaintext),
        hex::encode(plaintext)
    );

    let key = encryption::Key::new(main_key);

    let cipher = encryption::alg1::Algorithm1::new(&key, u32::from_be_bytes(index_key));
    let mut block = encryption::alg1::CipherBlock::new(plaintext);
    cipher.cipher_block(0, &mut block);
    println!("Encryption complete...");

    println!(
        "Ciphertext: {}, 0x{}",
        String::from_utf8_lossy(&block),
        hex::encode(&block)
    );

    println!("Encryption and decryption are the same operation, so simply enter the same keys and the cipher text to decrypt");
}
