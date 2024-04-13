use anyhow::{anyhow, Result};
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use chacha20poly1305::{
    aead::{stream, Aead},
    KeyInit, XChaCha20Poly1305,
};
use os_str_bytes::OsStrBytes;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::{
    fs::File,
    io::{Read, Write},
};

pub fn encrypt(plain_text: &[u8], token: &[u8]) -> Result<String> {
    // init encryptor
    let xkey: &[u8; 32] = token[..32].try_into().unwrap();
    let xnonce: &[u8; 24] = token[27..51].try_into().unwrap();
    let cipher = XChaCha20Poly1305::new(xkey.as_ref().into());
    // encrypt
    let cipher_text = cipher
        .encrypt(xnonce[..].into(), plain_text)
        .map_err(|err| anyhow!("Encrypting text: {}", err))?;
    Ok(
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD)
            .encode(cipher_text),
    )
}

pub fn decrypt(cipher_text: String, token: &[u8]) -> Result<OsString> {
    // init encryptor
    let xkey: &[u8; 32] = token[..32].try_into().unwrap();
    let xnonce: &[u8; 24] = token[27..51].try_into().unwrap();
    let cipher = XChaCha20Poly1305::new(xkey.as_ref().into());
    // decrypt
    let decoded_cipher = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD)
        .decode(cipher_text)?;
    let plain_text = cipher
        .decrypt(xnonce[..].into(), &decoded_cipher[..])
        .map_err(|err| anyhow!("Decrypting text: {}", err))?;
    match OsStr::from_io_bytes(&plain_text) {
        Some(os_str) => Ok(os_str.into()),
        None => Err(anyhow!("Failed to convert decrypted text to OsStr")),
    }
}

pub fn encrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    source: P,
    dist: Q,
    token: &[u8],
) -> Result<()> {
    // init encryptor
    let xkey: &[u8; 32] = token[..32].try_into().unwrap();
    let xnonce: &[u8; 19] = token[32..51].try_into().unwrap();
    let aead = XChaCha20Poly1305::new(xkey.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, xnonce.as_ref().into());
    // encrypt each part
    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];
    let mut source_file = File::open(source.as_ref())?;
    let mut dist_file = File::create(dist.as_ref())?;
    loop {
        let read_count = source_file.read(&mut buffer)?;
        if read_count == BUFFER_LEN {
            let cipher_text = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting file: {}", err))?;
            dist_file.write_all(&cipher_text)?;
        } else {
            let cipher_text = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting file: {}", err))?;
            dist_file.write_all(&cipher_text)?;
            break;
        }
    }
    Ok(())
}

pub fn decrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    source: P,
    dist: Q,
    token: &[u8],
) -> Result<()> {
    // init encryptor
    let xkey: &[u8; 32] = token[..32].try_into().unwrap();
    let xnonce: &[u8; 19] = token[32..51].try_into().unwrap();
    let aead = XChaCha20Poly1305::new(xkey.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, xnonce.as_ref().into());
    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];
    let mut encrypted_file = File::open(source.as_ref())?;
    let mut dist_file = File::create(dist.as_ref())?;
    loop {
        let read_count = encrypted_file.read(&mut buffer)?;
        if read_count == BUFFER_LEN {
            let plain_text = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting file: {}", err))?;
            dist_file.write_all(&plain_text)?;
        } else if read_count == 0 {
            break;
        } else {
            let plain_text = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting file: {}", err))?;
            dist_file.write_all(&plain_text)?;
            break;
        }
    }
    Ok(())
}

pub fn encrypt_file_name(source: &Path, token: &[u8]) -> Result<String> {
    let source_file_name = source
        .file_name()
        .ok_or_else(|| anyhow!("Failed to get source file name"))?
        .to_io_bytes_lossy();
    // encrypt dist file name
    let encrypted_file_name = encrypt(&source_file_name, token)?;
    // get dir name
    let dir_name = source
        .parent()
        .ok_or_else(|| anyhow!("Failed to get dir name"))?;
    Ok(format!(
        "{}.crab",
        dir_name.join(encrypted_file_name).display()
    ))
}

pub fn decrypt_file_name(source: &Path, token: &[u8]) -> Result<String> {
    let source_file_stem = source
        .file_stem()
        .ok_or_else(|| anyhow!("Failed to get source file name"))?
        .to_str()
        .ok_or_else(|| anyhow!("Failed to get source file name"))?
        .to_string();
    // decrypt dist file name
    let decrypted_file_name = decrypt(source_file_stem, token)?;
    // get dir name
    let dir_name = source
        .parent()
        .ok_or_else(|| anyhow!("Failed to get dir name"))?;
    Ok(format!("{}", dir_name.join(decrypted_file_name).display()))
}

pub fn encrypt_dir_name(source: &Path, token: &[u8]) -> Result<String> {
    let source_dir_name = source
        .iter()
        .last()
        .ok_or_else(|| anyhow!("Failed to get source dir name"))?
        .to_io_bytes_lossy();
    // encrypt dist dir name
    let encrypted_dir_name = encrypt(&source_dir_name, token)?;
    // get dir name
    let dir_name = source
        .parent()
        .ok_or_else(|| anyhow!("Failed to get dir name"))?;
    Ok(format!(
        "{}[crab]",
        dir_name.join(encrypted_dir_name).display()
    ))
}

pub fn decrypt_dir_name(source: &Path, token: &[u8]) -> Result<String> {
    let source_dir_name = source
        .iter()
        .last()
        .ok_or_else(|| anyhow!("Failed to get source dir name"))?
        .to_str()
        .ok_or_else(|| anyhow!("Failed to get source dir name"))?;
    let source_dir_name = source_dir_name[..source_dir_name.len() - 6].to_owned();
    // decrypt dist dir name
    let decrypted_dir_name = decrypt(source_dir_name, token)?;
    // get dir name
    let dir_name = source
        .parent()
        .ok_or_else(|| anyhow!("Failed to get dir name"))?;
    Ok(format!("{}", dir_name.join(decrypted_dir_name).display()))
}
