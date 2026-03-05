use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use thiserror::Error;

const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const DEK_SIZE: usize = 32;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key generation failed: {0}")]
    KeyGenFailed(String),
    #[error("Invalid payload format")]
    InvalidPayload,
}

pub struct HybridKeypair {
    pub pq_public: Vec<u8>,
    pub pq_secret: Vec<u8>,
    pub x25519_private: StaticSecret,
    pub x25519_public: PublicKey,
}

pub struct EncryptedPayload {
    pub pq_ciphertext: Vec<u8>,
    pub x25519_ephemeral: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
}

impl EncryptedPayload {
    pub fn serialize(&self) -> Vec<u8> {
        let parts: Vec<&[u8]> = vec![
            &self.pq_ciphertext,
            &self.x25519_ephemeral,
            &self.salt,
            &self.nonce,
            &self.ciphertext,
        ];
        let mut out = Vec::new();
        for part in &parts {
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        }
        for part in &parts {
            out.extend_from_slice(part);
        }
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 20 {
            return Err(CryptoError::InvalidPayload);
        }
        let mut lengths = [0u32; 5];
        for i in 0..5 {
            lengths[i] = u32::from_be_bytes(
                data[i * 4..(i + 1) * 4]
                    .try_into()
                    .map_err(|_| CryptoError::InvalidPayload)?,
            );
        }
        let mut offset = 20;
        let mut parts = Vec::new();
        for &len in &lengths {
            let len = len as usize;
            if offset + len > data.len() {
                return Err(CryptoError::InvalidPayload);
            }
            parts.push(data[offset..offset + len].to_vec());
            offset += len;
        }
        Ok(Self {
            pq_ciphertext: parts[0].clone(),
            x25519_ephemeral: parts[1].clone(),
            salt: parts[2].clone(),
            nonce: parts[3].clone(),
            ciphertext: parts[4].clone(),
        })
    }
}

// Type aliases for the ML-KEM-768 key/ciphertext types
type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;
type Ct = ml_kem::Ciphertext<MlKem768>;

pub fn generate_keypair() -> Result<HybridKeypair, CryptoError> {
    let (dk, ek) = MlKem768::generate(&mut OsRng);

    let ek_bytes = ek.as_bytes();
    let pq_public: Vec<u8> = AsRef::<[u8]>::as_ref(&ek_bytes).to_vec();
    let dk_bytes = dk.as_bytes();
    let pq_secret: Vec<u8> = AsRef::<[u8]>::as_ref(&dk_bytes).to_vec();

    let x25519_private = StaticSecret::random_from_rng(OsRng);
    let x25519_public = PublicKey::from(&x25519_private);

    Ok(HybridKeypair {
        pq_public,
        pq_secret,
        x25519_private,
        x25519_public,
    })
}

fn combine_shared_secrets(pq_ss: &[u8], x25519_ss: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut combined = Vec::new();
    combined.extend_from_slice(pq_ss);
    combined.extend_from_slice(x25519_ss);

    let hkdf = Hkdf::<Sha256>::new(Some(salt), &combined);
    let mut dek = vec![0u8; DEK_SIZE];
    hkdf.expand(b"pqvault-hybrid-dek-v1", &mut dek)
        .expect("HKDF expand failed");
    dek
}

pub fn hybrid_encrypt(
    plaintext: &[u8],
    pq_public: &[u8],
    x25519_public_bytes: &[u8],
) -> Result<EncryptedPayload, CryptoError> {
    // Reconstruct encapsulation key from bytes
    let ek_encoded: Encoded<Ek> = ml_kem::array::Array::try_from(pq_public)
        .map_err(|_| CryptoError::EncryptionFailed("Invalid PQ public key size".into()))?;
    let ek = Ek::from_bytes(&ek_encoded);

    // PQ key encapsulation
    let (pq_ct, pq_ss) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| CryptoError::EncryptionFailed("PQ encapsulation failed".into()))?;

    // Classical key exchange (ephemeral)
    let ephemeral_sk = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);
    let recipient_pk_bytes: [u8; 32] = x25519_public_bytes
        .try_into()
        .map_err(|_| CryptoError::EncryptionFailed("Invalid X25519 public key size".into()))?;
    let recipient_pk = PublicKey::from(recipient_pk_bytes);
    let x25519_ss = ephemeral_sk.diffie_hellman(&recipient_pk);

    // Combine shared secrets
    let mut salt = vec![0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let dek = combine_shared_secrets(pq_ss.as_ref(), x25519_ss.as_bytes(), &salt);

    // Symmetric encryption
    let mut nonce_bytes = vec![0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&dek)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: b"pqvault-v1",
            },
        )
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    Ok(EncryptedPayload {
        pq_ciphertext: AsRef::<[u8]>::as_ref(&pq_ct).to_vec(),
        x25519_ephemeral: ephemeral_pk.as_bytes().to_vec(),
        nonce: nonce_bytes,
        ciphertext,
        salt,
    })
}

pub fn hybrid_decrypt(
    payload: &EncryptedPayload,
    pq_secret: &[u8],
    x25519_private: &StaticSecret,
) -> Result<Vec<u8>, CryptoError> {
    // Reconstruct decapsulation key from bytes
    let dk_encoded: Encoded<Dk> = ml_kem::array::Array::try_from(pq_secret)
        .map_err(|_| CryptoError::DecryptionFailed("Invalid PQ secret key size".into()))?;
    let dk = Dk::from_bytes(&dk_encoded);

    // Reconstruct ciphertext
    let ct: Ct = ml_kem::array::Array::try_from(payload.pq_ciphertext.as_slice())
        .map_err(|_| CryptoError::DecryptionFailed("Invalid PQ ciphertext size".into()))?;

    // PQ decapsulation
    let pq_ss = dk
        .decapsulate(&ct)
        .map_err(|_| CryptoError::DecryptionFailed("PQ decapsulation failed".into()))?;

    // Classical key exchange
    let ephemeral_pk_bytes: [u8; 32] = payload
        .x25519_ephemeral
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("Invalid ephemeral key size".into()))?;
    let ephemeral_pk = PublicKey::from(ephemeral_pk_bytes);
    let x25519_ss = x25519_private.diffie_hellman(&ephemeral_pk);

    // Combine shared secrets
    let dek = combine_shared_secrets(pq_ss.as_ref(), x25519_ss.as_bytes(), &payload.salt);

    // Symmetric decryption
    let cipher = Aes256Gcm::new_from_slice(&dek)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let nonce = Nonce::from_slice(&payload.nonce);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &payload.ciphertext,
                aad: b"pqvault-v1",
            },
        )
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    Ok(plaintext)
}

// Password-based encryption (for protecting keypairs at rest)

pub fn password_encrypt(plaintext: &[u8], password: &str) -> Result<Vec<u8>, CryptoError> {
    let mut salt = vec![0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key_from_password(password, &salt)?;

    let mut nonce_bytes = vec![0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: b"pqvault-pw-v1",
            },
        )
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let mut out = Vec::new();
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn password_decrypt(data: &[u8], password: &str) -> Result<Vec<u8>, CryptoError> {
    if data.len() < SALT_SIZE + NONCE_SIZE {
        return Err(CryptoError::InvalidPayload);
    }
    let salt = &data[..SALT_SIZE];
    let nonce_bytes = &data[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
    let ct = &data[SALT_SIZE + NONCE_SIZE..];
    let key = derive_key_from_password(password, salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad: b"pqvault-pw-v1",
            },
        )
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    Ok(plaintext)
}

fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let params = scrypt::Params::new(17, 8, 1, DEK_SIZE)
        .map_err(|e| CryptoError::KeyGenFailed(e.to_string()))?;
    let mut key = vec![0u8; DEK_SIZE];
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut key)
        .map_err(|e| CryptoError::KeyGenFailed(e.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_encrypt_decrypt() {
        let plaintext = b"hello world secret data";
        let password = "test-password-123!";
        let encrypted = password_encrypt(plaintext, password).unwrap();
        let decrypted = password_decrypt(&encrypted, password).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_password_decrypt_wrong_password() {
        let plaintext = b"secret";
        let encrypted = password_encrypt(plaintext, "right").unwrap();
        assert!(password_decrypt(&encrypted, "wrong").is_err());
    }

    #[test]
    fn test_hybrid_encrypt_decrypt() {
        let kp = generate_keypair().unwrap();
        let plaintext = b"quantum-safe secret data here";
        let x25519_pub_bytes = kp.x25519_public.as_bytes().to_vec();
        let payload = hybrid_encrypt(plaintext, &kp.pq_public, &x25519_pub_bytes).unwrap();
        let decrypted = hybrid_decrypt(&payload, &kp.pq_secret, &kp.x25519_private).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_payload_serialize_deserialize() {
        let kp = generate_keypair().unwrap();
        let plaintext = b"roundtrip test";
        let x25519_pub_bytes = kp.x25519_public.as_bytes().to_vec();
        let payload = hybrid_encrypt(plaintext, &kp.pq_public, &x25519_pub_bytes).unwrap();
        let serialized = payload.serialize();
        let deserialized = EncryptedPayload::deserialize(&serialized).unwrap();
        let decrypted =
            hybrid_decrypt(&deserialized, &kp.pq_secret, &kp.x25519_private).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
