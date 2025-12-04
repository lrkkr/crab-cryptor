use crate::{decrypt_reader::DecryptReader, encrypt_writer::EncryptWriter};
use anyhow::{anyhow, Ok, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use chacha20poly1305::{
    aead::{stream, Aead},
    Key, KeyInit, XChaCha20Poly1305,
};
use flate2::read::GzDecoder;
use flate2::{write::GzEncoder, Compression};
use os_str_bytes::OsStrBytes;
use rand::{rng, RngCore};
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::{
    fs::File,
    io::{Read, Write},
};
use tar::{Archive, Builder};

pub const MAGIC_HEADER: &[u8] = b"CRABv4";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 19;
const NAME_NONCE_LEN: usize = 24;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    // 64MB RAM, 3 iterations, 4 parallelism
    let params = Params::new(64 * 1024, 3, 4, Some(32))
        .map_err(|e| anyhow!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Derivation failed: {}", e))?;

    Ok(key)
}

pub fn encrypt_name_core(plain_text: &[u8], key: &[u8; 32]) -> Result<String> {
    // init cipher
    let cipher = XChaCha20Poly1305::new(key.into());

    // generate Nonce
    let mut nonce = [0u8; NAME_NONCE_LEN];
    rng().fill_bytes(&mut nonce);
    let nonce_generic = chacha20poly1305::aead::generic_array::GenericArray::from_slice(&nonce);

    // encrypt
    // Tag will be appended
    let ciphertext = cipher
        .encrypt(nonce_generic, plain_text)
        .map_err(|err| anyhow!("Encrypting filename: {}", err))?;

    // concat [Nonce] + [Ciphertext]
    let mut packed = Vec::with_capacity(nonce.len() + ciphertext.len());
    packed.extend_from_slice(&nonce);
    packed.extend_from_slice(&ciphertext);

    // Base64
    Ok(engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD).encode(packed))
}

pub fn decrypt_name_core(encrypted_name_b64: &str, key: &[u8; 32]) -> Result<OsString> {
    // Base64
    let packed = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD)
        .decode(encrypted_name_b64)?;

    // check length Nonce 24 + Tag 16
    if packed.len() < NAME_NONCE_LEN + 16 {
        return Err(anyhow!("Invalid encrypted filename format"));
    }

    // split Nonce and content
    let (nonce, ciphertext) = packed.split_at(NAME_NONCE_LEN);

    // init cipher
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_generic = chacha20poly1305::aead::generic_array::GenericArray::from_slice(nonce);

    // decrypt
    let plain_text = cipher
        .decrypt(nonce_generic, ciphertext)
        .map_err(|err| anyhow!("Decrypting filename: {}", err))?;

    // to OsString
    match OsStr::from_io_bytes(&plain_text) {
        Some(os_str) => Ok(os_str.into()),
        None => Err(anyhow!("Failed to convert decrypted text to OsStr")),
    }
}

pub fn encrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    source: P,
    dist: Q,
    password: &str,
) -> Result<()> {
    let source_path = source.as_ref();
    let mut dist_file = File::create(dist.as_ref())?;

    // write magic header
    dist_file.write_all(MAGIC_HEADER)?;

    // generate and write random salt
    let mut salt = [0u8; SALT_LEN];
    rng().fill_bytes(&mut salt);
    dist_file.write_all(&salt)?;

    // generate and write random nonce
    let mut nonce = [0u8; NONCE_LEN];
    rng().fill_bytes(&mut nonce);
    dist_file.write_all(&nonce)?;

    // derive key
    let key_bytes = derive_key(password, &salt)?;
    let key = Key::from_slice(&key_bytes);

    let aead = XChaCha20Poly1305::new(key);
    let nonce_generic = chacha20poly1305::aead::generic_array::GenericArray::from_slice(&nonce);

    // build encrypt pipeline
    let stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce_generic);
    let encrypted_writer = EncryptWriter::new(dist_file, stream_encryptor);
    let gz_encoder = GzEncoder::new(encrypted_writer, Compression::default());
    let mut tar_builder = Builder::new(gz_encoder);

    // execute
    let file_name = source_path
        .file_name()
        .ok_or_else(|| anyhow!("No filename"))?;
    let mut source_file = File::open(source_path)?;
    tar_builder.append_file(file_name, &mut source_file)?;

    // flush
    let gz = tar_builder.into_inner()?;
    let enc = gz.finish()?;

    let mut final_file = enc.finish()?;
    final_file.flush()?;

    Ok(())
}

pub fn decrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    source: P,
    dist_dir: Q,
    password: &str,
) -> Result<()> {
    let source_path = source.as_ref();
    let mut source_file = File::open(source_path)?;

    let mut header = vec![0u8; MAGIC_HEADER.len()];
    source_file.read_exact(&mut header)?;
    if header != MAGIC_HEADER {
        return Err(anyhow!("Invalid file header: not a valid encrypted file"));
    }

    let mut salt = [0u8; SALT_LEN];
    source_file.read_exact(&mut salt)?;

    let mut nonce = [0u8; NONCE_LEN];
    source_file.read_exact(&mut nonce)?;

    let key_bytes = derive_key(password, &salt)?;
    let key = Key::from_slice(&key_bytes);

    let aead = XChaCha20Poly1305::new(key);
    let nonce_generic = chacha20poly1305::aead::generic_array::GenericArray::from_slice(&nonce);
    let stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce_generic);

    let decrypted_reader = DecryptReader::new(source_file, stream_decryptor);

    let gz_decoder = GzDecoder::new(decrypted_reader);

    let mut archive = Archive::new(gz_decoder);

    archive.unpack(dist_dir)?;

    Ok(())
}

pub fn encrypt_file_name(source: &Path, key: &[u8; 32]) -> Result<String> {
    let source_file_name = source
        .file_name()
        .ok_or_else(|| anyhow!("Failed to get source file name"))?
        .to_io_bytes_lossy();

    let encrypted_file_name = encrypt_name_core(&source_file_name, key)?;

    let dir_name = source
        .parent()
        .ok_or_else(|| anyhow!("Failed to get dir name"))?;

    Ok(format!(
        "{}.crab",
        dir_name.join(encrypted_file_name).display()
    ))
}

pub fn encrypt_dir_name(source: &Path, key: &[u8; 32]) -> Result<String> {
    let source_dir_name = source
        .iter()
        .next_back()
        .ok_or_else(|| anyhow!("Failed to get source dir name"))?
        .to_io_bytes_lossy();

    let encrypted_dir_name = encrypt_name_core(&source_dir_name, key)?;

    let dir_name = source
        .parent()
        .ok_or_else(|| anyhow!("Failed to get dir name"))?;

    Ok(format!(
        "{}[crab]",
        dir_name.join(encrypted_dir_name).display()
    ))
}

pub fn decrypt_dir_name(source: &Path, key: &[u8; 32]) -> Result<String> {
    let source_dir_str = source
        .iter()
        .next_back()
        .ok_or_else(|| anyhow!("Failed to get source dir name"))?
        .to_str()
        .ok_or_else(|| anyhow!("Failed to get source dir name"))?;

    // remove [crab]
    if source_dir_str.len() < 6 {
        return Err(anyhow!("Invalid directory name format"));
    }
    let encrypted_part = &source_dir_str[..source_dir_str.len() - 6];

    let decrypted_os_str = decrypt_name_core(encrypted_part, key)?;
    let decrypted_dir_name = decrypted_os_str.to_string_lossy();

    let dir_name = source
        .parent()
        .ok_or_else(|| anyhow!("Failed to get dir name"))?;

    Ok(format!(
        "{}",
        dir_name.join(decrypted_dir_name.as_ref()).display()
    ))
}
