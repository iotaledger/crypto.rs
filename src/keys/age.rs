// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// https://age-encryption.org/v1

use core::convert::TryFrom;

use aead::NewAead;
use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64, Engine as _};
use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305};
use hkdf::Hkdf;
use hmac_::{Hmac, Mac};
use scrypt::{scrypt, Params as ScryptParams};
use sha2::Sha256;
use zeroize::Zeroize;

// header with 1-digit work factor
const SCRYPT_MIN_HEADER_LEN: usize = 149;

// header with 2-digit work factor
const SCRYPT_MAX_HEADER_LEN: usize = 150;

const SALT_BASE64_LEN: usize = 22;

const ENCRYPTED_FILE_KEY_BASE64_LEN: usize = 43;

const MAC_BASE64_LEN: usize = 43;

/// Wrap key is derived from password & salt via scrypt KDF.
/// Wrap key is used to protect file key.
fn derive_wrap_key(password: &[u8], salt: &[u8; 16], work_factor: u8, wrap_key: &mut [u8; 32]) {
    // wrap key = scrypt(N = work factor, r = 8, p = 1, dkLen = 32,
    //     S = "age-encryption.org/v1/scrypt" || salt, P = passphrase)
    let params = ScryptParams::new(work_factor, 8, 1, 32).unwrap();
    const SALT_LABEL: &[u8; 28] = b"age-encryption.org/v1/scrypt";
    let mut scrypt_salt = [0_u8; SALT_LABEL.len() + 16];
    scrypt_salt[..SALT_LABEL.len()].copy_from_slice(SALT_LABEL);
    scrypt_salt[SALT_LABEL.len()..].copy_from_slice(&salt[..]);
    scrypt(password, &scrypt_salt[..], &params, &mut wrap_key[..]).expect("wrap_key is the correct length");
    scrypt_salt.zeroize();
}

/// File key is encrypted with wrap key via ChaCha20-Poly1305 with zero nonce and empty aad.
/// Body contains encrypted file key and authentication tag.
fn enc_file_key(password: &[u8], salt: &[u8; 16], work_factor: u8, file_key: &[u8; 16], body: &mut [u8; 16 + 16]) {
    let mut wrap_key = [0_u8; 32];
    derive_wrap_key(password, salt, work_factor, &mut wrap_key);
    // body+tag = ChaCha20-Poly1305(key = wrap key, plaintext = file key)
    let c = ChaCha20Poly1305::new(&wrap_key.into());
    wrap_key.zeroize();
    body[..16].copy_from_slice(&file_key[..]);
    let tag = c
        .encrypt_in_place_detached(&[0; 12].into(), &[], &mut body[..16])
        .expect("the ChaCha20 block counter doesn't overflow");
    body[16..].copy_from_slice(&tag);
}

/// Body contains encrypted file key and authentication tag.
/// Encrypted file key is decrypted with wrap key via ChaCha20-Poly1305 with zero nonce and empty aad.
fn dec_file_key(
    password: &[u8],
    salt: &[u8; 16],
    work_factor: u8,
    body: &[u8],
    file_key: &mut [u8; 16],
) -> Result<(), Error> {
    let mut wrap_key = [0_u8; 32];
    derive_wrap_key(password, salt, work_factor, &mut wrap_key);
    // body+tag = ChaCha20-Poly1305(key = wrap key, plaintext = file key)
    let c = ChaCha20Poly1305::new(&wrap_key.into());
    wrap_key.zeroize();
    file_key.copy_from_slice(&body[..16]);
    let mut tag = [0_u8; 16];
    tag.copy_from_slice(&body[16..32]);
    let r = c
        .decrypt_in_place_detached(&[0; 12].into(), &[], file_key, &tag.into())
        .map_err(|_| Error::BadFileKey);
    if r.is_err() {
        file_key.zeroize();
    }
    tag.zeroize();
    r
}

/// Mac key is derived from file key without salt via HKDF with SHA256.
/// Mac key is used to authenticate header.
fn derive_hmac_key(file_key: &[u8; 16], hmac_key: &mut [u8; 32]) {
    // mac key = HKDF-SHA-256(ikm = file key, salt = none, info = "header")
    Hkdf::<Sha256>::new(None, &file_key[..])
        .expand(b"header", &mut hmac_key[..])
        .expect("file_key and hmac_key are the correct length");
}

/// Payload key is derived from file key with nonce as salt via HKDF with SHA256.
/// Payload key is used to encrypt payload chunks.
fn derive_payload_key(file_key: &[u8; 16], nonce: &[u8; 16], payload_key: &mut [u8; 32]) {
    // payload key = HKDF-SHA-256(ikm = file key, salt = nonce, info = "payload")
    Hkdf::<Sha256>::new(Some(&nonce[..]), &file_key[..])
        .expand(b"payload", &mut payload_key[..])
        .expect("file_key and payload_key are the correct length");
}

/// Compute header MAC with mac key derived from file key.
fn mac_header(file_key: &[u8; 16], header: &[u8], mac: &mut [u8; 32]) {
    let mut hmac_key = [0_u8; 32];
    derive_hmac_key(file_key, &mut hmac_key);
    let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key[..]).unwrap();
    hmac_key.zeroize();
    // exclude the last ' ' after '---'
    hmac.update(header);
    mac.copy_from_slice(&hmac.finalize().into_bytes());
}

/// Verify header MAC with mac key derived from file key.
fn verify_mac_header(file_key: &[u8; 16], header: &[u8], mac: &[u8]) -> Result<(), Error> {
    let mut hmac_key = [0_u8; 32];
    derive_hmac_key(file_key, &mut hmac_key);
    let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key[..]).unwrap();
    hmac_key.zeroize();
    // exclude the last ' ' after '---'
    hmac.update(header);
    hmac.verify_slice(&mac[..32]).map_err(|_| Error::BadHeaderMac)
}

/// Length of header in bytes depends only on work factor.
/// The rest of the header is fixed-length.
const fn header_len(work_factor: u8) -> usize {
    // with 10 <= work_factor < 64 the header is fixed-length -- 150 bytes
    debug_assert!(work_factor < 64);
    SCRYPT_MIN_HEADER_LEN + if work_factor < 10 { 0 } else { 1 }
}

/// Encode header given password, salt, file key and work factor.
///
/// Arguments:
/// * `password` -- secret string
/// * `file_key` -- random 128-bit key used to derive other keys and compute MACs
/// * `salt` -- 16-byte random salt
/// * `work_factor` -- base-2 logarithm of scrypt work factor in decimal, `10 <= work_factor < 64`; work factor is
///   2-digit so that the header is fixed-length
///
/// Return:
/// * Length of the encoded header.
fn enc_header(password: &[u8], salt: &[u8; 16], file_key: &[u8; 16], work_factor: u8, header: &mut [u8]) -> usize {
    let mut i = 0_usize;
    debug_assert!(header_len(work_factor) <= header.len());

    // 1. AGE prefix
    // 2. version
    // 3. scrypt recipient stanza
    let b = b"age-encryption.org/v1\n-> scrypt ";
    header[i..i + b.len()].copy_from_slice(b);
    i += b.len();

    // 4. scrypt base64-encoded salt
    let b = BASE64.encode_slice(salt, &mut header[i..]).unwrap();
    debug_assert_eq!(SALT_BASE64_LEN, b);
    i += b;

    // 5. 1 or 2 decimal digit work factor
    header[i] = b' ';
    i += 1;
    if 10 <= work_factor {
        header[i] = b'0' + work_factor / 10;
        i += 1;
    }
    header[i] = b'0' + work_factor % 10;
    i += 1;
    header[i] = b'\n';
    i += 1;

    // encrypt file key
    let mut body = [0_u8; 16 + 16];
    enc_file_key(password, salt, work_factor, file_key, &mut body);

    // 6. base64-encoded encrypted file key
    let b = BASE64.encode_slice(body, &mut header[i..]).unwrap();
    debug_assert_eq!(ENCRYPTED_FILE_KEY_BASE64_LEN, b);
    i += b;

    // 7. final delimiter before MAC
    let b = b"\n--- ";
    header[i..i + b.len()].copy_from_slice(b);
    i += b.len();

    // MAC computed over the entire header up to and including '---'
    let mut mac = [0_u8; 32];
    // exclude the last ' ' after '---'
    mac_header(file_key, &header[..i - 1], &mut mac);

    // 8. base64-encoded MAC
    let b = BASE64.encode_slice(mac, &mut header[i..]).unwrap();
    debug_assert_eq!(MAC_BASE64_LEN, b);
    i += b;

    // 9. final new-line
    header[i] = b'\n';
    i += 1;

    // 10. binary encrypted payload

    i
}

/// Helper condition checker for decoding.
#[inline]
fn guard<E>(expr: bool, err: E) -> Result<(), E> {
    if expr {
        Ok(())
    } else {
        Err(err)
    }
}

/// Decode header given password and decrypt file key.
/// Length of decoded header is returned, or error.
fn dec_header(password: &[u8], max_work_factor: u8, header: &[u8], file_key: &mut [u8; 16]) -> Result<usize, Error> {
    let mut i = 0_usize;
    guard(header.len() >= SCRYPT_MIN_HEADER_LEN, Error::BufferTooSmall)?;

    // 1. AGE prefix
    let b = b"age-encryption.org/";
    guard(header[i..i + b.len()] == b[..], Error::UnknownFormat)?;
    i += b.len();

    // 2. version
    let b = b"v1\n";
    guard(header[i..i + b.len()] == b[..], Error::UnsupportedAgeVersion)?;
    i += b.len();

    // 3. scrypt recipient stanza
    let b = b"-> scrypt ";
    guard(header[i..i + b.len()] == b[..], Error::UnsupportedAgeRecipient)?;
    i += b.len();

    // 4. scrypt base64-encoded salt
    // extra 2 bytes for base64 decoding
    let mut salt2 = [0_u8; 16 + 2];
    let b = BASE64
        .decode_slice(&header[i..i + SALT_BASE64_LEN], &mut salt2)
        .map_err(|_| Error::BadAgeFormat)?;
    guard(16 == b, Error::BadAgeFormat)?;
    i += SALT_BASE64_LEN;
    let mut salt = [0_u8; 16];
    salt.copy_from_slice(&salt2[..16]);

    // 5. 1 or 2 decimal digit work factor
    let mut work_factor;
    guard(header[i] == b' ', Error::BadAgeFormat)?;
    i += 1;
    guard(char::from(header[i]).is_ascii_digit(), Error::BadAgeFormat)?;
    work_factor = header[i] - b'0';
    i += 1;
    if char::from(header[i]).is_ascii_digit() {
        guard(header.len() >= SCRYPT_MAX_HEADER_LEN, Error::BufferTooSmall)?;

        work_factor *= 10;
        work_factor += header[i] - b'0';
        i += 1;
    }
    guard(header[i] == b'\n', Error::BadAgeFormat)?;
    i += 1;
    guard(work_factor <= max_work_factor, Error::WorkFactorTooBig)?;

    // 6. base64-encoded encrypted file key
    // extra 2 bytes for base64 decoding
    let mut body2 = [0_u8; 16 + 16 + 2];
    let b = BASE64
        .decode_slice(&header[i..i + ENCRYPTED_FILE_KEY_BASE64_LEN], &mut body2[..])
        .map_err(|_| Error::BadAgeFormat)?;
    guard(16 + 16 == b, Error::BadAgeFormat)?;
    i += ENCRYPTED_FILE_KEY_BASE64_LEN;

    // decrypt file key
    dec_file_key(password, &salt, work_factor, &body2, file_key)?;

    // 7. final delimiter before MAC
    let b = b"\n--- ";
    guard(header[i..i + b.len()] == b[..], Error::BadAgeFormat)?;
    i += b.len();

    // 8. base64-encoded MAC
    // extra 2 bytes for base64 decoding
    let mut mac2 = [0_u8; 32 + 2];
    let b = BASE64
        .decode_slice(&header[i..i + MAC_BASE64_LEN], &mut mac2)
        .map_err(|_| Error::BadAgeFormat)?;
    guard(32 == b, Error::BadAgeFormat)?;

    // MAC computed over the entire header up to and including '---'
    // exclude the last ' ' after '---'
    verify_mac_header(file_key, &header[..i - 1], &mac2)?;
    i += MAC_BASE64_LEN;

    // 9. final new-line
    guard(header[i] == b'\n', Error::BadAgeFormat)?;
    i += 1;

    // 10. binary encrypted payload

    Ok(i)
}

/// Age decoding errors.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// Format is not `age-encryption.org`
    UnknownFormat,
    /// Version is not `v1`
    UnsupportedAgeVersion,
    /// Recipient is not `scrypt`
    UnsupportedAgeRecipient,
    /// Failed to parse parts of the header
    BadAgeFormat,
    /// Failed to decrypt file key: incorrect password or corrupt header
    BadFileKey,
    /// Header MAC is invalid: incorrect password or corrupt header
    BadHeaderMac,
    /// Failed to decrypt and verify payload chunk
    BadChunk,
    /// Input/output buffer (header) too small
    BufferTooSmall,
    /// Input/output buffer incorrect (unexpected) length
    BufferBadLength,
    /// Work factor during decryption exceeds maximum threshold value
    WorkFactorTooBig,
    /// Work factor representation is incorrect (>=64)
    IncorrectWorkFactor,
    /// Randomness generation failed
    RngFailed,
}

/// Nonce increment. Will never overflow in practice.
fn inc_nonce(nonce: &mut [u8; 12]) {
    for n in nonce[..11].iter_mut().rev() {
        *n = n.wrapping_add(1);
        if *n != 0 {
            break;
        }
    }
}

/// Encrypt payload chunk with payload key & nonce via ChaCha20-Poly1305.
fn enc_chunk(c: &ChaCha20Poly1305, nonce: &[u8; 12], plain_chunk: &[u8], cipher_chunk: &mut [u8]) {
    debug_assert_eq!(plain_chunk.len() + 16, cipher_chunk.len());
    debug_assert!(plain_chunk.len() <= 64 * 1024);

    // cipher chunk = ChaCha20-Poly1305(key = payload key, plaintext = plain chunk)
    cipher_chunk[..plain_chunk.len()].copy_from_slice(plain_chunk);
    let tag = c
        .encrypt_in_place_detached(nonce.into(), &[], &mut cipher_chunk[..plain_chunk.len()])
        .expect("the ChaCha20 block counter doesn't overflow");
    cipher_chunk[plain_chunk.len()..].copy_from_slice(&tag);
}

/// Decrypt and verify payload chunk with payload key & nonce via ChaCha20-Poly1305.
fn dec_chunk(c: &ChaCha20Poly1305, nonce: &[u8; 12], cipher_chunk: &[u8], plain_chunk: &mut [u8]) -> Result<(), Error> {
    debug_assert!(plain_chunk.len() <= 64 * 1024);
    debug_assert_eq!(plain_chunk.len() + 16, cipher_chunk.len());

    // cipher chunk = ChaCha20-Poly1305(key = payload key, plaintext = plain chunk)
    plain_chunk.copy_from_slice(&cipher_chunk[..plain_chunk.len()]);
    let mut tag = [0_u8; 16];
    tag.copy_from_slice(&cipher_chunk[plain_chunk.len()..]);
    let r = c
        .decrypt_in_place_detached(nonce.into(), &[], plain_chunk, &tag.into())
        .map_err(|_| Error::BadChunk);
    if r.is_err() {
        plain_chunk.zeroize();
    }
    tag.zeroize();
    r
}

/// Total length of ciphertext with nonce and authentication tags depending on plaintext length.
const fn enc_payload_len(plaintext_len: usize) -> usize {
    let num_chunks = if plaintext_len == 0 {
        1
    } else {
        (plaintext_len - 1) / (64 * 1024) + 1
    };
    16 + num_chunks * 16 + plaintext_len
}

/// The length of plaintext depending on ciphertext length.
/// Note, not all ciphertext lengths are valid.
pub const fn dec_payload_len(ciphertext_len: usize) -> Option<usize> {
    if ciphertext_len < 16 {
        // no 16-byte nonce
        None
    } else {
        let r = (ciphertext_len - 16) % (64 * 1024 + 16);
        let q = (ciphertext_len - 16) / (64 * 1024 + 16);
        if ((0 == q || 0 < r) && r < 16) || (0 < q && r == 16) {
            // no 16-byte tag in the last chunk, or
            // no empty last block allowed except for the first one
            None
        } else {
            let num_chunks = q + if 0 < r { 1 } else { 0 };
            Some(ciphertext_len - 16 - num_chunks * 16)
        }
    }
}

/// Encrypt the whole payload with file key and nonce.
/// Nonce is used to derive payload key and is prepended to ciphertext.
/// Note, nonce used to encrypt payload chunks is 12-byte counter.
fn enc_payload(file_key: &[u8; 16], nonce: &[u8; 16], mut plaintext: &[u8], ciphertext: &mut [u8]) {
    let mut i = 0_usize;

    debug_assert_eq!(enc_payload_len(plaintext.len()), ciphertext.len());

    ciphertext[i..i + 16].copy_from_slice(nonce);
    i += 16;

    let mut payload_key = [0_u8; 32];
    derive_payload_key(file_key, nonce, &mut payload_key);
    let c = ChaCha20Poly1305::new(&payload_key.into());
    payload_key.zeroize();

    // chunk encryption nonce; don't mix up with payload key derivation nonce
    let mut nonce = [0_u8; 12];

    loop {
        let s = core::cmp::min(64 * 1024, plaintext.len());
        if plaintext.len() == s {
            nonce[11] = 0x01;
        }
        enc_chunk(&c, &nonce, &plaintext[..s], &mut ciphertext[i..i + s + 16]);
        plaintext = &plaintext[s..];
        i += s + 16;
        if plaintext.is_empty() {
            break;
        }
        inc_nonce(&mut nonce);
    }
}

/// Decrypt the whole payload with file key and nonce.
/// Nonce is taken from the ciphertext.
/// Note, nonce used to encrypt payload chunks is 12-byte counter.
fn dec_payload(file_key: &[u8; 16], mut ciphertext: &[u8], plaintext: &mut [u8]) -> Result<usize, Error> {
    let mut i = 0_usize;
    // payload key derivation nonce
    let mut nonce = [0_u8; 16];

    if let Some(plaintext_len) = dec_payload_len(ciphertext.len()) {
        guard(plaintext_len <= plaintext.len(), Error::BufferTooSmall)?;
        debug_assert_eq!(enc_payload_len(plaintext_len), ciphertext.len());
    } else {
        guard(false, Error::BufferBadLength)?;
    }

    nonce.copy_from_slice(&ciphertext[..16]);
    ciphertext = &ciphertext[16..];

    let mut payload_key = [0_u8; 32];
    derive_payload_key(file_key, &nonce, &mut payload_key);
    let c = ChaCha20Poly1305::new(&payload_key.into());
    payload_key.zeroize();

    // chunk encryption nonce
    let mut nonce = [0_u8; 12];

    let r = loop {
        let s = core::cmp::min(64 * 1024 + 16, ciphertext.len());
        if ciphertext.len() == s {
            nonce[11] = 0x01;
        }
        let r = dec_chunk(&c, &nonce, &ciphertext[..s], &mut plaintext[i..i + s - 16]);
        if r.is_err() {
            break r;
        }
        ciphertext = &ciphertext[s..];
        i += s - 16;
        if ciphertext.is_empty() {
            break Ok(());
        }

        inc_nonce(&mut nonce);
    };

    if r.is_err() {
        plaintext.zeroize();
    }
    r.map(|_| i)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkFactor(u8);

impl WorkFactor {
    pub const fn new(work_factor: u8) -> Self {
        assert!(
            (work_factor as usize) < core::mem::size_of::<usize>() * 8,
            "incorrect age work factor"
        );
        Self(work_factor)
    }
}

impl TryFrom<u8> for WorkFactor {
    type Error = Error;
    fn try_from(work_factor: u8) -> Result<Self, Error> {
        if (work_factor as usize) < core::mem::size_of::<usize>() * 8 {
            Ok(Self(work_factor))
        } else {
            Err(Error::IncorrectWorkFactor)
        }
    }
}

impl From<WorkFactor> for u8 {
    fn from(work_factor: WorkFactor) -> u8 {
        work_factor.0
    }
}

/// The total age length including header and body depending on work factor and plaintext length.
pub const fn enc_len(work_factor: WorkFactor, plaintext_len: usize) -> usize {
    header_len(work_factor.0) + enc_payload_len(plaintext_len)
}

/// Encode header and encrypt payload given all the secrets and random inputs.
/// The length of the output can be be computed with `enc_len`.
///
/// The crucial security parameter (besides password strength) is `work_factor`.
/// Too small work factor (<15) will result in weak key derivation.
/// Too large work factor (>25) will take too long to derive key.
/// Recommended minimal value is `RECOMMENDED_MINIMUM_ENCRYPT_WORK_FACTOR`.
/// `work_factor` must be <64.
pub fn enc(
    password: &[u8],
    salt: &[u8; 16],
    file_key: &[u8; 16],
    work_factor: WorkFactor,
    nonce: &[u8; 16],
    plaintext: &[u8],
    age: &mut [u8],
) -> Result<usize, Error> {
    let age_len = enc_len(work_factor, plaintext.len());
    guard(age_len <= age.len(), Error::BufferTooSmall)?;
    let h = header_len(work_factor.0);
    enc_header(password, salt, file_key, work_factor.0, &mut age[..h]);
    enc_payload(file_key, nonce, plaintext, &mut age[h..age_len]);
    Ok(age_len)
}

/// Encode header and encrypt payload given all the secrets and random inputs producing a vector.
///
/// The crucial security parameter (besides password strength) is `work_factor`.
/// Too small work factor (<15) will result in weak key derivation.
/// Too large work factor (>25) will take too long to derive key.
/// Recommended minimal value is `RECOMMENDED_MINIMUM_ENCRYPT_WORK_FACTOR`.
/// `work_factor` must be <64.
#[cfg(feature = "std")]
pub fn enc_vec(
    password: &[u8],
    salt: &[u8; 16],
    file_key: &[u8; 16],
    work_factor: WorkFactor,
    nonce: &[u8; 16],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut age = Vec::new();
    age.resize(enc_len(work_factor, plaintext.len()), 0_u8);
    let h = enc_header(password, salt, file_key, work_factor.0, &mut age[..]);
    enc_payload(file_key, nonce, plaintext, &mut age[h..]);
    age
}

/// The recommended minimum work factor used by `encrypt`, or roughly 1 sec on modern PC (2023).
pub const RECOMMENDED_MINIMUM_ENCRYPT_WORK_FACTOR: u8 = 19;

/// Generate random salt, file key, and nonce and use them to protect plaintext in age format.
///
/// The crucial security parameter (besides password strength) is `work_factor`.
/// Too small work factor (<15) will result in weak key derivation.
/// Too large work factor (>25) will take too long to derive key.
/// Recommended minimal value is `RECOMMENDED_MINIMUM_ENCRYPT_WORK_FACTOR`.
/// `work_factor` must be <64.
#[cfg(feature = "random")]
pub fn encrypt(password: &[u8], work_factor: WorkFactor, plaintext: &[u8], age: &mut [u8]) -> Result<usize, Error> {
    let mut salt = [0_u8; 16];
    let mut file_key = [0_u8; 16];
    let mut nonce = [0_u8; 16];
    crate::utils::rand::fill(&mut salt[..]).map_err(|_| Error::RngFailed)?;
    crate::utils::rand::fill(&mut file_key[..]).map_err(|_| Error::RngFailed)?;
    crate::utils::rand::fill(&mut nonce[..]).map_err(|_| Error::RngFailed)?;
    let r = enc(password, &salt, &file_key, work_factor, &nonce, plaintext, age);
    nonce.zeroize();
    file_key.zeroize();
    salt.zeroize();
    r
}

/// Generate random salt, file key, and nonce and use them to protect plaintext in age format producing a vector.
#[cfg(all(feature = "random", feature = "std"))]
pub fn encrypt_vec(password: &[u8], work_factor: WorkFactor, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut salt = [0_u8; 16];
    let mut file_key = [0_u8; 16];
    let mut nonce = [0_u8; 16];
    crate::utils::rand::fill(&mut salt[..]).map_err(|_| Error::RngFailed)?;
    crate::utils::rand::fill(&mut file_key[..]).map_err(|_| Error::RngFailed)?;
    crate::utils::rand::fill(&mut nonce[..]).map_err(|_| Error::RngFailed)?;
    let age = enc_vec(password, &salt, &file_key, work_factor, &nonce, plaintext);
    nonce.zeroize();
    file_key.zeroize();
    salt.zeroize();
    Ok(age)
}

/// The recommended maximum work factor used by `decrypt`, or roughly 45 sec on modern PC (2023).
pub const RECOMMENDED_MAXIMUM_DECRYPT_WORK_FACTOR: u8 = 23;

/// Decrypt age format.
/// The length of the plaintext depends on the header (work factor) and can be approximated as
/// `dec_payload_len(age.len() - header_len(10)).unwrap()`.
///
/// `max_work_factor` parameter limits the amount of computation that the decryptor is willing to spend.
/// Too large values of work factor in the protected input age can result in DoS.
pub fn decrypt(password: &[u8], max_work_factor: u8, age: &[u8], plaintext: &mut [u8]) -> Result<usize, Error> {
    let mut file_key = [0_u8; 16];
    let r = dec_header(password, max_work_factor, age, &mut file_key)
        .and_then(|header_len| dec_payload(&file_key, &age[header_len..], plaintext));
    file_key.zeroize();
    r
}

/// Decrypt age format producing a vector.
///
/// `max_work_factor` parameter limits the amount of computation that the decryptor is willing to spend.
/// Too large values of work factor in the protected input age can result in DoS.
#[cfg(feature = "std")]
pub fn decrypt_vec(password: &[u8], max_work_factor: u8, age: &[u8]) -> Result<Vec<u8>, Error> {
    let mut file_key = [0_u8; 16];
    let r = dec_header(password, max_work_factor, age, &mut file_key).and_then(|header_len| {
        if let Some(plaintext_len) = dec_payload_len(age.len() - header_len) {
            let mut plaintext = Vec::new();
            plaintext.resize(plaintext_len, 0_u8);
            let _ = dec_payload(&file_key, &age[header_len..], &mut plaintext[..])?;
            Ok(plaintext)
        } else {
            Err(Error::BufferBadLength)
        }
    });
    file_key.zeroize();
    r
}

#[cfg(test)]
mod tests {
    const K64: usize = 64 * 1024;
    const TEST_LENS: [usize; 12] = [
        0,
        1,
        K64 - 16,
        K64 - 1,
        K64,
        K64 + 1,
        K64 + 16,
        2 * K64 - 16,
        2 * K64 - 1,
        2 * K64,
        2 * K64 + 1,
        2 * K64 + 16,
    ];

    #[test]
    fn test_payload_len() {
        for len in TEST_LENS {
            assert_eq!(Some(len), super::dec_payload_len(super::enc_payload_len(len)));
        }
        assert_eq!(None, super::dec_payload_len(0));
        assert_eq!(None, super::dec_payload_len(15));
        assert_eq!(None, super::dec_payload_len(16));
        assert_eq!(None, super::dec_payload_len(31));
        assert_eq!(Some(0), super::dec_payload_len(32));

        assert_eq!(Some(K64), super::dec_payload_len(16 + K64 + 16));
        assert_eq!(None, super::dec_payload_len(16 + K64 + 16 + 1));
        assert_eq!(None, super::dec_payload_len(16 + K64 + 16 + 16));
        assert_eq!(Some(K64 + 1), super::dec_payload_len(16 + K64 + 16 + 17));

        assert_eq!(Some(2 * K64), super::dec_payload_len(16 + 2 * (K64 + 16)));
        assert_eq!(None, super::dec_payload_len(16 + 2 * (K64 + 16) + 1));
        assert_eq!(None, super::dec_payload_len(16 + 2 * (K64 + 16) + 16));
        assert_eq!(Some(2 * K64 + 1), super::dec_payload_len(16 + 2 * (K64 + 16) + 17));
    }

    #[test]
    fn test_nonce() {
        let mut nonce = [0_u8; 12];
        for i in 1_usize..258_usize {
            super::inc_nonce(&mut nonce);
            assert_eq!(i.to_be_bytes(), &nonce[3..11]);
        }
    }

    fn run_header(
        password: &[u8],
        salt: &[u8; 16],
        file_key: &[u8; 16],
        work_factor: u8,
        max_work_factor: u8,
    ) -> Result<(), super::Error> {
        let mut header = [0_u8; super::SCRYPT_MAX_HEADER_LEN];
        let h = super::enc_header(
            password,
            salt,
            file_key,
            work_factor,
            &mut header[..super::header_len(work_factor)],
        );
        let mut dec_file_key = [0_u8; 16];
        let r = super::dec_header(password, max_work_factor, &header, &mut dec_file_key);
        if r.is_ok() {
            assert_eq!(h, r.unwrap());
            assert_eq!(file_key, &dec_file_key);
        }
        r.map(|_| ())
    }

    #[test]
    fn test_header() {
        let password = [0xaa_u8; 1025];
        let pwd_lens = [0, 1, 33, 65, 1025];
        let bits = [[0x00_u8; 16], [0xaa_u8; 16], [0xff_u8; 16]];
        let work_factor = 1_u8;

        // run_header(&password[..0], &bits[2], &bits[2], 10);
        for pwd_len in pwd_lens {
            for salt in bits {
                for file_key in bits {
                    let r = run_header(&password[..pwd_len], &salt, &file_key, work_factor, work_factor);
                    assert!(r.is_ok());
                }
            }
        }
    }

    #[cfg(feature = "std")]
    fn enc_crate(plaintext: &[u8]) -> Vec<u8> {
        use core::convert::TryInto;
        let password = "password".as_bytes();
        let work_factor = 1_u8.try_into().unwrap();
        let salt = [0x11_u8; 16];
        let file_key = [0x22_u8; 16];
        let nonce = [0x33_u8; 16];
        super::enc_vec(password, &salt, &file_key, work_factor, &nonce, plaintext)
    }

    #[cfg(feature = "std")]
    fn enc_rage(plaintext: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let password = "password".to_owned().into();
        let mut age = Vec::new();
        let mut writer = age::Encryptor::with_user_passphrase(password)
            .wrap_output(&mut age)
            .unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();
        age
    }

    #[cfg(feature = "std")]
    fn dec_crate(age: &[u8], max_work_factor: u8) -> Option<Vec<u8>> {
        super::decrypt_vec("password".as_bytes(), max_work_factor, age).ok()
    }

    #[cfg(feature = "std")]
    fn dec_rage(age: &[u8]) -> Option<Vec<u8>> {
        use std::io::Read;
        let pass = "password".to_owned().into();
        let mut reader = match age::Decryptor::new(age).unwrap() {
            age::Decryptor::Recipients(_) => panic!("internal error"),
            age::Decryptor::Passphrase(d) => d.decrypt(&pass, Some(14)).unwrap(),
        };
        let mut decrypted = Vec::new();
        reader.read_to_end(&mut decrypted).ok()?;
        Some(decrypted)
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_crate_rage() {
        for text_len in TEST_LENS {
            let mut plaintext = Vec::new();
            plaintext.resize(text_len, 0xaa_u8);
            let decrypted = dec_rage(&enc_crate(&plaintext));
            assert_eq!(Some(plaintext), decrypted);
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_crate_crate() {
        for text_len in TEST_LENS {
            let mut plaintext = Vec::new();
            plaintext.resize(text_len, 0xaa_u8);
            let decrypted = dec_crate(&enc_crate(&plaintext), 1_u8);
            assert_eq!(Some(plaintext), decrypted);
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_rage_crate() {
        for text_len in [0, 1, 64 * 1024 + 1] {
            let mut plaintext = Vec::new();
            plaintext.resize(text_len, 0xaa_u8);
            let max_work_factor = 22_u8;
            // dec_crate can fail if max_work_factor is too small
            let decrypted = dec_crate(&enc_rage(&plaintext), max_work_factor);
            assert_eq!(Some(plaintext), decrypted);
        }
    }

    #[test]
    fn test_fuzz() {
        let plain = [0xdd_u8; 5];
        let mut decrypted = [0_u8; 5];
        const WORK_FACTOR: super::WorkFactor = super::WorkFactor::new(1_u8);
        let mut age = [0_u8; super::enc_len(WORK_FACTOR, 5)];

        let salt = [0x11_u8; 16];
        let file_key = [0x22_u8; 16];
        let nonce = [0x33_u8; 16];
        assert!(super::enc(b"password", &salt, &file_key, WORK_FACTOR, &nonce, &plain, &mut age).is_ok());

        assert!(super::decrypt(b"password", 1_u8, &age, &mut decrypted).is_ok());
        assert_eq!(&plain, &decrypted);
        assert!(super::decrypt(b"password", 0_u8, &age, &mut decrypted).is_err());

        assert!(super::decrypt(b"passphrase", 1_u8, &age, &mut decrypted).is_err());
        for i in 0..age.len() {
            age[i] ^= 1;
            assert!(super::decrypt(b"password", 2_u8, &age, &mut decrypted).is_err());
            age[i] ^= 1;
        }
    }
}
