use std::{fs, path::PathBuf};

use aes_gcm::{
    aead::{generic_array::GenericArray, AeadMut},
    aes::cipher::typenum::{
        bit::{B0, B1},
        UInt, UTerm,
    },
    Aes128Gcm, KeyInit, Nonce,
};
use base64;
use pbkdf2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Pbkdf2,
};
use rand::{distributions::Alphanumeric, Rng};
use rsa::{
    pkcs1::EncodeRsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey},
    PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey,
};

const RSA_KEY_LENGTH: usize = 2048;
const AES_NONCE_LENGTH: usize = 96 / 8;
const AES_SALT_LENGTH: usize = 128 / 8;
const AES_HASH_LENGTH: usize = 128 / 8;

pub const RSA_PRIV_KEY_FILENAME: &str = "priv_key.der.enc";
pub const RSA_PUB_KEY_FILENAME: &str = "pub_key.pem";

type Aes128Key = GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>;

#[derive(Debug, Clone, Copy)]
pub enum CryptoError {
    NoRsaPrivateKeyFound,
    RsaFailedEncryption,
    RsaFailedDecryption,

    CryptoMachineLocked,
    CryptoMachineUnlocked,
    InvalidPassphrase,

    RsaKeyNotDumped,
}

pub struct RsaCipher {
    pub priv_key: Option<RsaPrivateKey>,
    pub pub_key: RsaPublicKey,
}

pub struct CryptoMachine {
    cipher: RsaCipher,
    pub_key_dump: String,
    priv_key_dump: String,
    is_locked: bool,
}

impl RsaCipher {
    pub fn new() -> Self {
        let priv_key = RsaPrivateKey::new(&mut OsRng, RSA_KEY_LENGTH)
            .expect("Unable to generate RSA private key!");
        RsaCipher::from_priv_key(priv_key)
    }

    pub fn from_priv_key(priv_key: RsaPrivateKey) -> Self {
        let pub_key = RsaPublicKey::from(&priv_key);
        let priv_key = Some(priv_key);
        Self { priv_key, pub_key }
    }

    pub fn from_pub_key(pub_key: RsaPublicKey) -> Self {
        let priv_key = None;
        Self { priv_key, pub_key }
    }

    pub fn encrypt_bytes(&self, buffer: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self
            .pub_key
            .encrypt(&mut OsRng, PaddingScheme::new_pkcs1v15_encrypt(), &buffer)
        {
            Ok(result) => Ok(result),
            Err(_) => Err(CryptoError::RsaFailedEncryption),
        }
    }

    pub fn decrypt_bytes(&self, buffer: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Check if private key is available
        // Otherwise, return error
        let priv_key = match &self.priv_key {
            Some(priv_key) => priv_key,
            None => return Err(CryptoError::NoRsaPrivateKeyFound),
        };

        // Decrypt byte
        match priv_key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &buffer) {
            Ok(result) => Ok(result),
            Err(_) => Err(CryptoError::RsaFailedDecryption),
        }
    }
}

impl CryptoMachine {
    pub fn new(passphrase: String) -> Self {
        // Create a new RSA cipher
        let mut cipher = RsaCipher::new();

        // Dump keys
        let pub_key_string = Self::dump_rsa_pub_key(&cipher.pub_key);
        let priv_key_string = Self::dump_rsa_priv_key(&cipher.priv_key.unwrap(), passphrase);

        // Delete the unencrypted private key
        cipher.priv_key = None;
        let is_locked = true;
        Self {
            cipher,
            pub_key_dump: pub_key_string,
            priv_key_dump: priv_key_string,
            is_locked,
        }
    }

    pub fn from_key_dump(pub_key_dump: String, priv_key_dump: String) -> Self {
        // Create encrypt-only cipher
        let pub_key = Self::load_rsa_pub_key(&pub_key_dump);
        let cipher = RsaCipher::from_pub_key(pub_key);

        let is_locked = true;
        Self {
            cipher,
            pub_key_dump,
            priv_key_dump,
            is_locked,
        }
    }

    pub fn from_repository(repository_dir: &PathBuf) -> Self {
        // Load public key dump
        let pub_key_dump = repository_dir.join(RSA_PUB_KEY_FILENAME);
        let pub_key_dump = fs::read_to_string(pub_key_dump).unwrap();

        // Load encrypted private key dump
        let priv_key_dump = repository_dir.join(RSA_PRIV_KEY_FILENAME);
        let priv_key_dump = fs::read_to_string(priv_key_dump).unwrap();

        // Instantiate from key dumps
        Self::from_key_dump(pub_key_dump, priv_key_dump)
    }

    pub fn to_repository(self, repository_dir: &PathBuf) -> Result<(), CryptoError> {
        if !self.is_locked {
            return Err(CryptoError::CryptoMachineUnlocked);
        }

        // Write public key dump
        match fs::write(repository_dir.join(RSA_PUB_KEY_FILENAME), self.pub_key_dump) {
            Ok(_) => (),
            Err(_) => return Err(CryptoError::RsaKeyNotDumped),
        }
        match fs::write(
            repository_dir.join(RSA_PRIV_KEY_FILENAME),
            self.priv_key_dump,
        ) {
            Ok(_) => (),
            Err(_) => return Err(CryptoError::RsaKeyNotDumped),
        }
        Ok(())
    }

    pub fn pub_key_dump(&self) -> &String {
        &self.pub_key_dump
    }

    pub fn priv_key_dump(&self) -> Result<&String, CryptoError> {
        if self.is_locked {
            Ok(&self.priv_key_dump)
        } else {
            Err(CryptoError::CryptoMachineUnlocked)
        }
    }

    pub fn unlock(&mut self, passphrase: String) -> Result<&mut Self, CryptoError> {
        self.try_unlock(passphrase);
        if !self.is_locked {
            Ok(self)
        } else {
            Err(CryptoError::InvalidPassphrase)
        }
    }

    pub fn try_unlock(&mut self, passphrase: String) -> &mut Self {
        // Check if private key already exists
        if !self.is_locked {
            return self;
        }

        // Decrypt private key with passphrase
        let priv_key = match Self::load_rsa_priv_key(&self.priv_key_dump, passphrase) {
            Ok(k) => {
                self.is_locked = false;
                Some(k)
            }
            Err(_) => None,
        };

        // Set private key
        self.cipher.priv_key = priv_key;
        self
    }

    pub fn lock(&mut self, passphrase: String) -> &mut Self {
        // Check if private key does not exist
        if self.is_locked {
            return self;
        }

        // Encrypt private key with passphrase
        let priv_key_string =
            Self::dump_rsa_priv_key(&self.cipher.priv_key.as_ref().unwrap(), passphrase);

        // Remove unencrypted private key
        self.cipher.priv_key = None;

        // Save new private key string (in case of passphrase change)
        self.priv_key_dump = priv_key_string;
        self
    }

    pub fn decrypt(&mut self, buffer: &Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        if self.is_locked {
            return Err(CryptoError::CryptoMachineLocked);
        }

        self.cipher.decrypt_bytes(&buffer[..])
    }

    pub fn try_decrypt(&mut self, buffer: &mut Vec<u8>) -> &mut Self {
        if self.is_locked {
            return self;
        }

        // Decrypt bytes using cipher
        *buffer = self.cipher.decrypt_bytes(&buffer[..]).unwrap();
        self
    }

    pub fn encrypt(&mut self, buffer: &Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        self.cipher.encrypt_bytes(&buffer[..])
    }

    pub fn try_encrypt(&mut self, buffer: &mut Vec<u8>) -> &mut Self {
        // Encrypt bytes using cipher
        *buffer = self.cipher.encrypt_bytes(&buffer[..]).unwrap();
        self
    }

    fn generate_nonce_string() -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(AES_NONCE_LENGTH)
            .map(char::from)
            .collect()
    }

    fn dump_rsa_priv_key(priv_key: &RsaPrivateKey, passphrase: String) -> String {
        // Process private key into document
        let priv_doc = priv_key.to_pkcs8_der().unwrap();

        // Perform PBKDF2 to generate key from passphrase
        let salt = SaltString::generate(&mut OsRng);
        let key = Pbkdf2
            .hash_password(passphrase.as_bytes(), &salt)
            .unwrap()
            .hash
            .unwrap();

        // Separate key into 2 parts: Encryption key and hash
        // Hash is the second half of the key (byte 16-31, bit 128-255),
        // while encryption key is the first half of the key (byte 0-15, bit 0-127).
        //
        // Encryption will be used for the actual encryption of the private key,
        // while hash is used to verify that the passphrase is correct without performing decryption.
        //
        // Hash is stored in a vector, which is then extended by appending the salt used for PBKDF2.
        // Length of salt string is 16 bytes as per recommendation.
        let mut hash = Vec::from(&key.as_bytes()[16..32]);

        let mut salt_buffer = [0u8; AES_SALT_LENGTH];
        salt.b64_decode(&mut salt_buffer).unwrap();
        hash.extend(salt_buffer);

        let key = &key.as_bytes()[..16];
        let key: Aes128Key = GenericArray::clone_from_slice(&key);

        // Cipher will be created from encryption key
        let mut cipher = Aes128Gcm::new(&key);

        // Another nonce is created every time the private key is encrypted
        // Add nonce to 'hash' as well
        let nonce = Self::generate_nonce_string();
        hash.extend(nonce.as_bytes());
        let nonce = Nonce::from_slice(nonce.as_bytes());

        // Encrypt private key document
        let ciphertext = cipher.encrypt(nonce, priv_doc.as_bytes()).unwrap();

        // Append the ciphertext to hash
        // Hence, hash will occupy from index 0 - 15, salt will occupy from index 16 - 31,
        // while the actual cipher text will occupy from index 32 onwards.
        hash.extend(ciphertext);
        base64::encode(&hash[..])
    }

    fn load_rsa_priv_key(data: &String, passphrase: String) -> Result<RsaPrivateKey, CryptoError> {
        // Decompose data
        let data = base64::decode(data).unwrap();

        let mut offset: usize = 0;
        let hash = &data[..AES_HASH_LENGTH];
        offset += AES_HASH_LENGTH;
        let salt = &data[offset..offset + AES_SALT_LENGTH];
        offset += AES_SALT_LENGTH;
        let nonce = &data[offset..offset + AES_NONCE_LENGTH];
        String::from_utf8(nonce.to_vec()).unwrap();
        let nonce = Nonce::from_slice(nonce);
        offset += AES_NONCE_LENGTH;
        let ciphertext = &data[offset..];

        // Recreate key from salt and passphrase
        let salt = SaltString::b64_encode(salt).unwrap();
        let key = Pbkdf2
            .hash_password(passphrase.as_bytes(), &salt)
            .unwrap()
            .hash
            .unwrap();

        // Split the key as during encryption
        let gen_hash = Vec::from(&key.as_bytes()[16..32]);

        // Verify that the hash matches before performing decryption
        if hash != &gen_hash[..] {
            return Err(CryptoError::InvalidPassphrase);
        }

        let key = &key.as_bytes()[..16];
        let key: Aes128Key = GenericArray::clone_from_slice(&key);

        let mut cipher = Aes128Gcm::new(&key);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .expect("Failed to decrypt secret key document!");

        Ok(RsaPrivateKey::from_pkcs8_der(&plaintext[..])
            .expect("Failed to unpack secret key document!"))
    }

    fn dump_rsa_pub_key(pub_key: &RsaPublicKey) -> String {
        pub_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("Failed to convert public key to standardised document!")
    }

    fn load_rsa_pub_key(data: &String) -> RsaPublicKey {
        RsaPublicKey::from_public_key_pem(data).expect("Failed to unpack public key document!")
    }
}
