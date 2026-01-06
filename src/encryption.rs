use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};

#[derive(Clone)]
pub struct KeyAndNonce {
    pub cipher: ChaCha20Poly1305,
    pub counter: u128
}

impl KeyAndNonce {
    pub fn new(key: [u8; 32], _nonce_prefix: [u8; 16], counter: u128) -> Result<KeyAndNonce,()> {
        let cipher = match ChaCha20Poly1305::new_from_slice(&key) {
            Ok(c) => c,
            Err(_) => {
                println!("Failed to create cipher");
                return Err(());
            }
        };
        Ok(KeyAndNonce {cipher, counter})
    }
    pub fn encrypt(&mut self, buf: &mut Vec<u8>) -> Result<(),()> {
        let nonce = self.counter.to_le_bytes();
        self.counter += 1;
        let nonce = Nonce::from_slice(&nonce[0..12]);
        match self.cipher.encrypt_in_place(&nonce, &[0u8; 0], buf) {
            Ok(()) => Ok(()),
            Err(_) => Err(())
        }
    }
    pub fn decrypt(&mut self, buf: &mut Vec<u8>) -> Result<(),()> {
        let nonce = self.counter.to_le_bytes();
        self.counter += 1;
        let nonce = Nonce::from_slice(&nonce[0..12]);
        match self.cipher.decrypt_in_place(&nonce, &[0u8; 0], buf) {
            Ok(()) => Ok(()),
            Err(_) => Err(())
        }
    }
}

