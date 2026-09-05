use super::{version::QuicVersionProfile, EndpointRole};
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::aead::AeadInPlace;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use hkdf::Hkdf;
use rustls::quic::{HeaderProtectionKey, PacketKey, Tag};
use sha2::{Sha256, Sha384};
use std::fmt;
use zeroize::Zeroizing;

const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HP_SAMPLE_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicCipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl QuicCipherSuite {
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }

    #[must_use]
    pub const fn secret_len(self) -> usize {
        match self {
            Self::Aes256GcmSha384 => 48,
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid QUIC traffic secret length: expected {expected}, got {actual}")]
    InvalidSecretLength { expected: usize, actual: usize },
    #[error("HKDF label or output is too long")]
    HkdfLength,
    #[error("invalid QUIC key material")]
    InvalidKey,
}

pub trait QuicCryptoProvider: Send + Sync {
    fn derive_initial_keys(
        &self,
        version: &'static QuicVersionProfile,
        dcid: &[u8],
        role: EndpointRole,
    ) -> Result<DirectionalKeys, CryptoError>;

    fn derive_traffic_keys(
        &self,
        version: &'static QuicVersionProfile,
        suite: QuicCipherSuite,
        secret: &[u8],
    ) -> Result<DirectionalKeys, CryptoError>;

    fn derive_next_secret(
        &self,
        version: &'static QuicVersionProfile,
        suite: QuicCipherSuite,
        secret: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RustCryptoProvider;

impl QuicCryptoProvider for RustCryptoProvider {
    fn derive_initial_keys(
        &self,
        version: &'static QuicVersionProfile,
        dcid: &[u8],
        role: EndpointRole,
    ) -> Result<DirectionalKeys, CryptoError> {
        let initial = Hkdf::<Sha256>::new(Some(&version.initial_salt), dcid);
        let label = match role {
            EndpointRole::Client => b"client in".as_slice(),
            EndpointRole::Server => b"server in".as_slice(),
        };
        let secret = expand_sha256(&initial, label, 32)?;
        derive_sha256_keys(version, QuicCipherSuite::Aes128GcmSha256, &secret)
    }

    fn derive_traffic_keys(
        &self,
        version: &'static QuicVersionProfile,
        suite: QuicCipherSuite,
        secret: &[u8],
    ) -> Result<DirectionalKeys, CryptoError> {
        validate_secret(suite, secret)?;
        match suite {
            QuicCipherSuite::Aes256GcmSha384 => derive_sha384_keys(version, suite, secret),
            QuicCipherSuite::Aes128GcmSha256 | QuicCipherSuite::ChaCha20Poly1305Sha256 => {
                derive_sha256_keys(version, suite, secret)
            }
        }
    }

    fn derive_next_secret(
        &self,
        version: &'static QuicVersionProfile,
        suite: QuicCipherSuite,
        secret: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        validate_secret(suite, secret)?;
        let next = match suite {
            QuicCipherSuite::Aes256GcmSha384 => {
                let hkdf = Hkdf::<Sha384>::from_prk(secret).map_err(|_| CryptoError::InvalidKey)?;
                expand_sha384(&hkdf, version.update_label, suite.secret_len())?
            }
            QuicCipherSuite::Aes128GcmSha256 | QuicCipherSuite::ChaCha20Poly1305Sha256 => {
                let hkdf = Hkdf::<Sha256>::from_prk(secret).map_err(|_| CryptoError::InvalidKey)?;
                expand_sha256(&hkdf, version.update_label, suite.secret_len())?
            }
        };
        Ok(Zeroizing::new(next))
    }
}

fn validate_secret(suite: QuicCipherSuite, secret: &[u8]) -> Result<(), CryptoError> {
    let expected = suite.secret_len();
    if secret.len() != expected {
        return Err(CryptoError::InvalidSecretLength {
            expected,
            actual: secret.len(),
        });
    }
    Ok(())
}

fn derive_sha256_keys(
    version: &'static QuicVersionProfile,
    suite: QuicCipherSuite,
    secret: &[u8],
) -> Result<DirectionalKeys, CryptoError> {
    let hkdf = Hkdf::<Sha256>::from_prk(secret).map_err(|_| CryptoError::InvalidKey)?;
    assemble_keys(
        suite,
        expand_sha256(&hkdf, version.key_label, suite.key_len())?,
        expand_sha256(&hkdf, version.iv_label, IV_LEN)?,
        expand_sha256(&hkdf, version.hp_label, suite.key_len())?,
    )
}

fn derive_sha384_keys(
    version: &'static QuicVersionProfile,
    suite: QuicCipherSuite,
    secret: &[u8],
) -> Result<DirectionalKeys, CryptoError> {
    let hkdf = Hkdf::<Sha384>::from_prk(secret).map_err(|_| CryptoError::InvalidKey)?;
    assemble_keys(
        suite,
        expand_sha384(&hkdf, version.key_label, suite.key_len())?,
        expand_sha384(&hkdf, version.iv_label, IV_LEN)?,
        expand_sha384(&hkdf, version.hp_label, suite.key_len())?,
    )
}

fn expand_sha256(
    hkdf: &Hkdf<Sha256>,
    label: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let info = hkdf_label(label, output_len)?;
    let mut output = vec![0; output_len];
    hkdf.expand(&info, &mut output)
        .map_err(|_| CryptoError::HkdfLength)?;
    Ok(output)
}

fn expand_sha384(
    hkdf: &Hkdf<Sha384>,
    label: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let info = hkdf_label(label, output_len)?;
    let mut output = vec![0; output_len];
    hkdf.expand(&info, &mut output)
        .map_err(|_| CryptoError::HkdfLength)?;
    Ok(output)
}

fn hkdf_label(label: &[u8], output_len: usize) -> Result<Vec<u8>, CryptoError> {
    let output_len = u16::try_from(output_len).map_err(|_| CryptoError::HkdfLength)?;
    let label_len = 6usize
        .checked_add(label.len())
        .ok_or(CryptoError::HkdfLength)?;
    let label_len = u8::try_from(label_len).map_err(|_| CryptoError::HkdfLength)?;
    let mut info = Vec::with_capacity(2 + 1 + usize::from(label_len) + 1);
    info.extend_from_slice(&output_len.to_be_bytes());
    info.push(label_len);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    Ok(info)
}

fn assemble_keys(
    suite: QuicCipherSuite,
    key: Vec<u8>,
    iv: Vec<u8>,
    header_key: Vec<u8>,
) -> Result<DirectionalKeys, CryptoError> {
    let iv: [u8; IV_LEN] = iv.try_into().map_err(|_| CryptoError::InvalidKey)?;
    Ok(DirectionalKeys {
        packet_key: QuicPacketKey::new(suite, key, iv)?,
        header_key: QuicHeaderKey::new(suite, header_key)?,
    })
}

pub struct DirectionalKeys {
    packet_key: QuicPacketKey,
    header_key: QuicHeaderKey,
}

impl DirectionalKeys {
    #[must_use]
    pub fn packet_key(&self) -> &QuicPacketKey {
        &self.packet_key
    }

    #[must_use]
    pub fn header_key(&self) -> &QuicHeaderKey {
        &self.header_key
    }

    #[must_use]
    pub fn packet_key_bytes(&self) -> &[u8] {
        self.packet_key.key_bytes()
    }

    #[must_use]
    pub fn iv_bytes(&self) -> &[u8] {
        self.packet_key.iv_bytes()
    }

    #[must_use]
    pub fn header_key_bytes(&self) -> &[u8] {
        self.header_key.key_bytes()
    }

    fn into_parts(self) -> (QuicPacketKey, QuicHeaderKey) {
        (self.packet_key, self.header_key)
    }
}

impl fmt::Debug for DirectionalKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectionalKeys")
            .field("suite", &self.packet_key.suite())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct QuicPacketKey {
    suite: QuicCipherSuite,
    key: Zeroizing<Vec<u8>>,
    iv: Zeroizing<[u8; IV_LEN]>,
}

impl QuicPacketKey {
    fn new(suite: QuicCipherSuite, key: Vec<u8>, iv: [u8; IV_LEN]) -> Result<Self, CryptoError> {
        if key.len() != suite.key_len() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self {
            suite,
            key: Zeroizing::new(key),
            iv: Zeroizing::new(iv),
        })
    }

    #[must_use]
    pub const fn suite(&self) -> QuicCipherSuite {
        self.suite
    }

    #[must_use]
    pub fn key_bytes(&self) -> &[u8] {
        &self.key
    }

    #[must_use]
    pub fn iv_bytes(&self) -> &[u8] {
        self.iv.as_ref()
    }

    fn nonce(&self, packet_number: u64) -> [u8; IV_LEN] {
        let mut nonce = *self.iv;
        for (slot, value) in nonce[IV_LEN - 8..]
            .iter_mut()
            .zip(packet_number.to_be_bytes())
        {
            *slot ^= value;
        }
        nonce
    }
}

impl fmt::Debug for QuicPacketKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuicPacketKey")
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

impl PacketKey for QuicPacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, rustls::Error> {
        let nonce = self.nonce(packet_number);
        let tag = match self.suite {
            QuicCipherSuite::Aes128GcmSha256 => aes_gcm::Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| rustls::Error::EncryptError)?
                .encrypt_in_place_detached((&nonce).into(), header, payload)
                .map_err(|_| rustls::Error::EncryptError)?,
            QuicCipherSuite::Aes256GcmSha384 => aes_gcm::Aes256Gcm::new_from_slice(&self.key)
                .map_err(|_| rustls::Error::EncryptError)?
                .encrypt_in_place_detached((&nonce).into(), header, payload)
                .map_err(|_| rustls::Error::EncryptError)?,
            QuicCipherSuite::ChaCha20Poly1305Sha256 => {
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|_| rustls::Error::EncryptError)?
                    .encrypt_in_place_detached((&nonce).into(), header, payload)
                    .map_err(|_| rustls::Error::EncryptError)?
            }
        };
        Ok(Tag::from(tag.as_slice()))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], rustls::Error> {
        if payload.len() < TAG_LEN {
            return Err(rustls::Error::DecryptError);
        }
        let nonce = self.nonce(packet_number);
        let message_len = payload.len() - TAG_LEN;
        let (message, tag_bytes) = payload.split_at_mut(message_len);
        let tag = GenericArray::clone_from_slice(tag_bytes);
        match self.suite {
            QuicCipherSuite::Aes128GcmSha256 => aes_gcm::Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| rustls::Error::DecryptError)?
                .decrypt_in_place_detached((&nonce).into(), header, message, &tag),
            QuicCipherSuite::Aes256GcmSha384 => aes_gcm::Aes256Gcm::new_from_slice(&self.key)
                .map_err(|_| rustls::Error::DecryptError)?
                .decrypt_in_place_detached((&nonce).into(), header, message, &tag),
            QuicCipherSuite::ChaCha20Poly1305Sha256 => {
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|_| rustls::Error::DecryptError)?
                    .decrypt_in_place_detached((&nonce).into(), header, message, &tag)
            }
        }
        .map_err(|_| rustls::Error::DecryptError)?;
        Ok(message)
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        match self.suite {
            QuicCipherSuite::ChaCha20Poly1305Sha256 => u64::MAX,
            QuicCipherSuite::Aes128GcmSha256 | QuicCipherSuite::Aes256GcmSha384 => 1 << 23,
        }
    }

    fn integrity_limit(&self) -> u64 {
        match self.suite {
            QuicCipherSuite::ChaCha20Poly1305Sha256 => 1 << 36,
            QuicCipherSuite::Aes128GcmSha256 | QuicCipherSuite::Aes256GcmSha384 => 1 << 52,
        }
    }
}

#[derive(Clone)]
pub struct QuicHeaderKey {
    suite: QuicCipherSuite,
    key: Zeroizing<Vec<u8>>,
}

impl QuicHeaderKey {
    fn new(suite: QuicCipherSuite, key: Vec<u8>) -> Result<Self, CryptoError> {
        if key.len() != suite.key_len() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self {
            suite,
            key: Zeroizing::new(key),
        })
    }

    #[must_use]
    pub const fn suite(&self) -> QuicCipherSuite {
        self.suite
    }

    #[must_use]
    pub fn key_bytes(&self) -> &[u8] {
        &self.key
    }

    fn apply_mask(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        decrypting: bool,
    ) -> Result<(), rustls::Error> {
        if sample.len() != HP_SAMPLE_LEN || packet_number.len() > 4 {
            return Err(rustls::Error::General(
                "invalid QUIC header protection sample".into(),
            ));
        }
        let mask = self.mask(sample)?;
        let first_mask = if *first & 0x80 != 0 { 0x0f } else { 0x1f };
        let plain_first = if decrypting {
            *first ^ (mask[0] & first_mask)
        } else {
            *first
        };
        let packet_number_len = usize::from((plain_first & 0x03) + 1);
        if packet_number.len() < packet_number_len {
            return Err(rustls::Error::General(
                "QUIC packet number is truncated".into(),
            ));
        }
        *first ^= mask[0] & first_mask;
        for (byte, mask_byte) in packet_number
            .iter_mut()
            .zip(&mask[1..])
            .take(packet_number_len)
        {
            *byte ^= mask_byte;
        }
        Ok(())
    }

    fn mask(&self, sample: &[u8]) -> Result<[u8; 5], rustls::Error> {
        let mut mask = [0u8; 5];
        match self.suite {
            QuicCipherSuite::Aes128GcmSha256 => {
                let cipher = Aes128::new_from_slice(&self.key)
                    .map_err(|_| rustls::Error::General("invalid AES-128 HP key".into()))?;
                let mut block = GenericArray::clone_from_slice(sample);
                cipher.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            QuicCipherSuite::Aes256GcmSha384 => {
                let cipher = Aes256::new_from_slice(&self.key)
                    .map_err(|_| rustls::Error::General("invalid AES-256 HP key".into()))?;
                let mut block = GenericArray::clone_from_slice(sample);
                cipher.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            QuicCipherSuite::ChaCha20Poly1305Sha256 => {
                let counter = u32::from_le_bytes(sample[..4].try_into().expect("checked sample"));
                let mut cipher = chacha20::ChaCha20::new_from_slices(&self.key, &sample[4..])
                    .map_err(|_| rustls::Error::General("invalid ChaCha20 HP key".into()))?;
                cipher.seek(u64::from(counter) * 64);
                cipher.apply_keystream(&mut mask);
            }
        }
        Ok(mask)
    }
}

impl fmt::Debug for QuicHeaderKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuicHeaderKey")
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

impl HeaderProtectionKey for QuicHeaderKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        self.apply_mask(sample, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        self.apply_mask(sample, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        HP_SAMPLE_LEN
    }
}

pub struct KeyEpoch {
    secret: Zeroizing<Vec<u8>>,
    packet_key: QuicPacketKey,
}

impl KeyEpoch {
    #[must_use]
    pub fn packet_key(&self) -> &QuicPacketKey {
        &self.packet_key
    }

    #[must_use]
    pub fn packet_key_bytes(&self) -> &[u8] {
        self.packet_key.key_bytes()
    }
}

impl fmt::Debug for KeyEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyEpoch")
            .field("suite", &self.packet_key.suite())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct ApplicationKeySet {
    header_key: QuicHeaderKey,
    previous: Option<KeyEpoch>,
    current: KeyEpoch,
    next: KeyEpoch,
}

impl ApplicationKeySet {
    pub fn new(
        provider: &dyn QuicCryptoProvider,
        version: &'static QuicVersionProfile,
        suite: QuicCipherSuite,
        secret: &[u8],
    ) -> Result<Self, CryptoError> {
        let current_keys = provider.derive_traffic_keys(version, suite, secret)?;
        let next_secret = provider.derive_next_secret(version, suite, secret)?;
        let next_keys = provider.derive_traffic_keys(version, suite, &next_secret)?;
        let (current_packet_key, header_key) = current_keys.into_parts();
        let (next_packet_key, _) = next_keys.into_parts();
        Ok(Self {
            header_key,
            previous: None,
            current: KeyEpoch {
                secret: Zeroizing::new(secret.to_vec()),
                packet_key: current_packet_key,
            },
            next: KeyEpoch {
                secret: next_secret,
                packet_key: next_packet_key,
            },
        })
    }

    #[must_use]
    pub fn header_key(&self) -> &QuicHeaderKey {
        &self.header_key
    }

    #[must_use]
    pub fn header_key_bytes(&self) -> &[u8] {
        self.header_key.key_bytes()
    }

    #[must_use]
    pub fn previous(&self) -> Option<&KeyEpoch> {
        self.previous.as_ref()
    }

    #[must_use]
    pub const fn current(&self) -> &KeyEpoch {
        &self.current
    }

    #[must_use]
    pub const fn next(&self) -> &KeyEpoch {
        &self.next
    }

    pub fn rotate(
        &mut self,
        provider: &dyn QuicCryptoProvider,
        version: &'static QuicVersionProfile,
        suite: QuicCipherSuite,
    ) -> Result<(), CryptoError> {
        let fresh_secret = provider.derive_next_secret(version, suite, &self.next.secret)?;
        let fresh_keys = provider.derive_traffic_keys(version, suite, &fresh_secret)?;
        let (fresh_packet_key, _) = fresh_keys.into_parts();
        let fresh = KeyEpoch {
            secret: fresh_secret,
            packet_key: fresh_packet_key,
        };
        self.previous = Some(std::mem::replace(
            &mut self.current,
            std::mem::replace(&mut self.next, fresh),
        ));
        Ok(())
    }

    pub fn discard_previous(&mut self) {
        self.previous = None;
    }
}
