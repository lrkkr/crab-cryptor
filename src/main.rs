use anyhow::{anyhow, Result};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use chacha20poly1305::{
    aead::{stream, Aead},
    KeyInit, XChaCha20Poly1305,
};
use clap::{arg, Command};
use std::path::Path;
use std::{
    fs::File,
    io::{Read, Write},
};
use walkdir::WalkDir;

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
    let plain_text = cipher
        .decrypt(xnonce[..].into(), cipher_text.as_bytes())
        .map_err(|err| anyhow!("Decrypting text: {}", err))?;
    Ok(base64::encode(&plain_text))
}

pub fn encrypt_file<P: AsRef<Path>>(source: P, dist: P, token: &[u8]) -> Result<()> {
    // init encryptor
    let xkey: &[u8; 32] = token[..32].try_into().unwrap();
    let xnonce: &[u8; 19] = token[32..51].try_into().unwrap();
    let aead = XChaCha20Poly1305::new(xkey.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, xnonce.as_ref().into());
    // encrypt each part
    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];
    let mut source_file = File::open(source)?;
    let mut dist_file = File::create(dist)?;
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

pub fn decrypt_file<P: AsRef<Path>>(source: P, dist: P, token: &[u8]) -> Result<()> {
    // init encryptor
    let xkey: &[u8; 32] = token[..32].try_into().unwrap();
    let xnonce: &[u8; 19] = token[32..51].try_into().unwrap();
    let aead = XChaCha20Poly1305::new(xkey.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, xnonce.as_ref().into());
    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];
    let mut encrypted_file = File::open(source)?;
    let mut dist_file = File::create(dist)?;
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

fn main() -> Result<()> {
    let matches = Command::new("crab")
        .version("0.1")
        .author("xl_g <lr_kkr@outlook.com>")
        .about("A file cryptor")
        .arg(arg!(-e --encrypt <Token> "Encrypt dir").required(false))
        .arg(arg!(-d --decrypt <Token> "Decrypt dir").required(false))
        .get_matches();
    if let Some(token) = matches.get_one::<String>("encrypt") {
        // extend token
        let mut hasher = Blake2bVar::new(51).unwrap();
        hasher.update(token.as_bytes());
        let mut buf = [0u8; 51];
        hasher.finalize_variable(&mut buf).unwrap();
        // walk dir
        for entry in WalkDir::new("./").into_iter() {
            let entry = entry?;
            if entry.metadata()?.is_file() {
                let source = entry.path();
                println!("{}", source.display());
            }
        }
        // encrypt_file("test.txt", "test.txt.crab", &buf)?;
    }
    if let Some(token) = matches.get_one::<String>("decrypt") {
        // extend token
        let mut hasher = Blake2bVar::new(51).unwrap();
        hasher.update(token.as_bytes());
        let mut buf = [0u8; 51];
        hasher.finalize_variable(&mut buf).unwrap();
        // walk dir
        decrypt_file("test.txt.crab", "test.txt", &buf)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;

    use crate::encrypt;

    #[test]
    fn crypt_test() {
        let token = String::from("crab");
        let mut hasher = Blake2bVar::new(51).unwrap();
        hasher.update(token.as_bytes());
        let mut buf = [0u8; 51];
        hasher.finalize_variable(&mut buf).unwrap();
        let cipher_text = encrypt("plain_text".to_owned(), &buf).unwrap();
        assert_eq!(
            cipher_text,
            "zGEeAhLTe+2D7lkYnP1fLL9e67L8aEqrJ94=".to_owned()
        );
    }
}
