use rand::{Rng, RngCore};

fn main() {
    let mut rng = rand::rngs::OsRng;
    //Assert cryptographically secure
    let _: &dyn rand::CryptoRng = &rng;

    let mut plaintext = [0u8; 28];
    let mut key = [0u8; 1024];
    //rng.fill_bytes(&mut plaintext);
    rng.fill_bytes(&mut key);
    let key = encryption::Key::new(key);

    let cipher = encryption::alg1::MainCipher::new(&key, rng.gen());
    let mut block = encryption::alg1::CipherBlock::new(plaintext);
    cipher.cipher_block(0, &mut block);
    println!("{:b}", V(block.0.to_vec()));
}

fn run_tests(buf: &[u8], msg: impl AsRef<str>) {
    use rand_distr::{Distribution, Exp, Normal, StudentT};
    use statest::ks::*;

    let t = StudentT::new(1.0).unwrap();
    let t_vec = (0..1000)
        .map(|_| t.sample(&mut rand::thread_rng()))
        .collect::<Vec<f64>>();

    let tdist = StudentT::new(1.0f64).unwrap();
    let ndist = Normal::new(0.0f64, 1.0f64).unwrap();
    let edist = Exp::new(1.0f64).unwrap();
    //println!("StudentT? {}", t_vec.ks1(&tdist, 0.05f64)); // true
    //println!("Normal? {}", t_vec.ks1(&ndist, 0.05)); // false
    //println!("Exponential? {}", t_vec.ks1(&edist, 0.05)); // false
}

struct V(Vec<u8>);

impl std::fmt::Binary for V {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let vec = &self.0;

        for (count, n) in vec.iter().enumerate() {
            if count != 0 {
                write!(f, " ")?;
            }
            write!(f, "{:010b}", n)?;
        }

        Ok(())
    }
}
