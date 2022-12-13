use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{stream, Aead},
    KeyInit, XChaCha20Poly1305,
};
use regex::Regex;
use std::path::Path;
use std::{
    fs::File,
    io::{Read, Write},
};

pub fn encrypt(plain_text: String, token: &[u8]) -> Result<String> {
    // init encryptor
    let xkey: &[u8; 32] = token[..32].try_into().unwrap();
    let xnonce: &[u8; 24] = token[27..51].try_into().unwrap();
    let cipher = XChaCha20Poly1305::new(xkey.as_ref().into());
    // encrypt
    let cipher_text = cipher
        .encrypt(xnonce[..].into(), plain_text.as_bytes())
        .map_err(|err| anyhow!("Encrypting text: {}", err))?;
    Ok(base64::encode(&cipher_text))
}

pub fn decrypt(cipher_text: String, token: &[u8]) -> Result<String> {
    // init encryptor
    let xkey: &[u8; 32] = token[..32].try_into().unwrap();
    let xnonce: &[u8; 24] = token[27..51].try_into().unwrap();
    let cipher = XChaCha20Poly1305::new(xkey.as_ref().into());
    // decrypt
    let decoded_cipher = base64::decode(cipher_text)?;
    let plain_text = cipher
        .decrypt(xnonce[..].into(), &decoded_cipher[..])
        .map_err(|err| anyhow!("Decrypting text: {}", err))?;
    String::from_utf8(plain_text).map_err(|err| anyhow!("Decrypting text: {}", err))
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

pub fn get_encrypted_file_name(source: &Path, token: &[u8]) -> Result<String> {
    let source_file_name = source
        .file_name()
        .ok_or_else(|| anyhow!("Failed to get source file name"))?
        .to_str()
        .ok_or_else(|| anyhow!("Failed to get source file name"))?
        .to_string();
    // encrypt dist file name
    let encrypted_file_name = encrypt(source_file_name, token)?;
    // fix: / in encrypted_file_name
    let re = Regex::new(r"/").unwrap();
    let encrypted_file_name = re.replace_all(&encrypted_file_name, "_").to_string();
    // get dir name
    let dir_name = source
        .parent()
        .ok_or_else(|| anyhow!("Failed to get dir name"))?;
    Ok(format!(
        "{}.crab",
        dir_name.join(encrypted_file_name).display()
    ))
}

pub fn get_decrypted_file_name(source: &Path, token: &[u8]) -> Result<String> {
    let source_file_stem = source
        .file_stem()
        .ok_or_else(|| anyhow!("Failed to get source file name"))?
        .to_str()
        .ok_or_else(|| anyhow!("Failed to get source file name"))?
        .to_string();
    let re = Regex::new(r"_").unwrap();
    let source_file_stem = re.replace_all(&source_file_stem, "/").to_string();
    // decrypt dist file name
    let decrypted_file_name = decrypt(source_file_stem, token)?;
    // get dir name
    let dir_name = source
        .parent()
        .ok_or_else(|| anyhow!("Failed to get dir name"))?;
    Ok(format!("{}", dir_name.join(decrypted_file_name).display()))
}
