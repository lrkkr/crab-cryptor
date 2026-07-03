use crate::{decrypt_reader::DecryptReader, encrypt_writer::EncryptWriter};
use aead_stream::{DecryptorBE32, EncryptorBE32, StreamBE32};
use anyhow::{Context, Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{
    Engine as _, alphabet,
    engine::{self, general_purpose},
};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use flate2::read::GzDecoder;
use flate2::{Compression, write::GzEncoder};
use os_str_bytes::OsStrBytes;
use rand::{Rng, rng};
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
};
use tar::{Archive, Builder, EntryType};
use zeroize::Zeroizing;

pub const MAGIC_HEADER: &[u8] = b"CRABv4";
pub const NAME_MASTER_SALT: &[u8] = b"CrabFileNameSalt";
pub const MIN_ENCRYPTED_FILE_LEN: usize = MAGIC_HEADER.len() + SALT_LEN + NONCE_LEN + 16;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 19;
const NAME_NONCE_LEN: usize = 24;
const NAME_CONTEXT_SALT_LEN: usize = 16;
const NAME_V2_PREFIX: &str = "v2_";
const NAME_V3_MARKER: &[u8] = &[0xc3, 0x03];
const NAME_V3_KEY_DOMAIN: &[u8] = b"crab:name-key:v3";
const NAME_V3_AAD_DOMAIN: &[u8] = b"crab:name:v3";
const FILE_NAME_CONTEXT_LABEL: &[u8] = b"file-name";
const DIR_NAME_CONTEXT_LABEL: &[u8] = b"dir-name";

type XChaChaStreamNonce = aead_stream::Nonce<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>;

fn derive_key_from_secret(secret: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if salt.len() < 8 {
        return Err(anyhow!("Derivation salt must be at least 8 bytes"));
    }

    // 64MB RAM, 3 iterations, 4 parallelism
    let params =
        Params::new(64 * 1024, 3, 4, Some(32)).map_err(|e| anyhow!("Argon2 params error: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(secret, salt, &mut *key)
        .map_err(|e| anyhow!("Derivation failed: {e}"))?;

    Ok(key)
}

/// Derives a 256-bit key from a password and salt.
///
/// # Errors
/// Returns an error if Argon2 parameter construction or key derivation fails.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    derive_key_from_secret(password.as_bytes(), salt)
}

/// Derives a v2 per-parent name key from the stable name master key.
///
/// # Errors
/// Returns an error if the contextual Argon2 key derivation fails.
pub fn derive_name_key(
    master_key: &[u8; 32],
    encrypted_parent_relative: &Path,
    label: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let parent_relative = encrypted_parent_relative.as_os_str().to_io_bytes_lossy();

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crab:name-key:v2");
    hasher.update(label);
    hasher.update(&parent_relative);

    let digest = hasher.finalize();
    let mut salt = [0u8; NAME_CONTEXT_SALT_LEN];
    salt.copy_from_slice(&digest.as_bytes()[..NAME_CONTEXT_SALT_LEN]);

    derive_key_from_secret(master_key, &salt)
}

fn derive_v3_name_key(master_key: &[u8; 32], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_keyed(master_key);
    hasher.update(NAME_V3_KEY_DOMAIN);
    hasher.update(label);
    Zeroizing::new(*hasher.finalize().as_bytes())
}

fn v3_name_aad(label: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(NAME_V3_AAD_DOMAIN.len() + NAME_V3_MARKER.len() + label.len());
    aad.extend_from_slice(NAME_V3_AAD_DOMAIN);
    aad.extend_from_slice(NAME_V3_MARKER);
    aad.extend_from_slice(label);
    aad
}

fn encrypt_name_v3(plain_text: &[u8], master_key: &[u8; 32], label: &[u8]) -> Result<String> {
    let name_key = derive_v3_name_key(master_key, label);
    let cipher = XChaCha20Poly1305::new((&*name_key).into());

    let mut nonce = [0u8; NAME_NONCE_LEN];
    rng().fill_bytes(&mut nonce);
    let nonce_generic = XNonce::from(nonce);
    let aad = v3_name_aad(label);
    let ciphertext = cipher
        .encrypt(
            &nonce_generic,
            Payload {
                msg: plain_text,
                aad: &aad,
            },
        )
        .map_err(|err| anyhow!("Encrypting v3 filename: {err}"))?;

    let mut packed = Vec::with_capacity(nonce.len() + NAME_V3_MARKER.len() + ciphertext.len());
    packed.extend_from_slice(&nonce);
    packed.extend_from_slice(NAME_V3_MARKER);
    packed.extend_from_slice(&ciphertext);

    Ok(engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD).encode(packed))
}

fn decode_name(encrypted_name_b64: &str) -> Result<Vec<u8>> {
    Ok(
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD)
            .decode(encrypted_name_b64)?,
    )
}

fn has_v3_name_marker(encrypted_name_b64: &str) -> Result<bool> {
    let packed = decode_name(encrypted_name_b64)?;
    Ok(packed
        .get(NAME_NONCE_LEN..NAME_NONCE_LEN + NAME_V3_MARKER.len())
        .is_some_and(|marker| marker == NAME_V3_MARKER))
}

fn decrypt_name_v3(
    encrypted_name_b64: &str,
    master_key: &[u8; 32],
    label: &[u8],
) -> Result<OsString> {
    let packed = decode_name(encrypted_name_b64)?;
    let minimum_len = NAME_NONCE_LEN + NAME_V3_MARKER.len() + 16;
    if packed.len() < minimum_len {
        return Err(anyhow!("Invalid v3 encrypted filename format"));
    }

    let (nonce, marker_and_ciphertext) = packed.split_at(NAME_NONCE_LEN);
    let (marker, ciphertext) = marker_and_ciphertext.split_at(NAME_V3_MARKER.len());
    if marker != NAME_V3_MARKER {
        return Err(anyhow!("Invalid v3 encrypted filename marker"));
    }

    let name_key = derive_v3_name_key(master_key, label);
    let cipher = XChaCha20Poly1305::new((&*name_key).into());
    let nonce_generic = XNonce::try_from(nonce)?;
    let aad = v3_name_aad(label);
    let plain_text = cipher
        .decrypt(
            &nonce_generic,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|err| anyhow!("Decrypting v3 filename: {err}"))?;

    OsStr::from_io_bytes(&plain_text)
        .map(OsStr::to_os_string)
        .ok_or_else(|| anyhow!("Failed to convert decrypted v3 text to OsStr"))
}

/// Encrypts a file or directory name into URL-safe Base64.
///
/// # Errors
/// Returns an error if authenticated encryption fails.
pub fn encrypt_name_core(plain_text: &[u8], key: &[u8; 32]) -> Result<String> {
    // init cipher
    let cipher = XChaCha20Poly1305::new(key.into());

    // generate Nonce
    let mut nonce = [0u8; NAME_NONCE_LEN];
    rng().fill_bytes(&mut nonce);
    let nonce_generic = XNonce::from(nonce);

    // encrypt
    // Tag will be appended
    let ciphertext = cipher
        .encrypt(&nonce_generic, plain_text)
        .map_err(|err| anyhow!("Encrypting filename: {err}"))?;

    // concat [Nonce] + [Ciphertext]
    let mut packed = Vec::with_capacity(nonce.len() + ciphertext.len());
    packed.extend_from_slice(&nonce);
    packed.extend_from_slice(&ciphertext);

    // Base64
    Ok(engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD).encode(packed))
}

/// Decrypts a URL-safe Base64 encoded name back into an OS string.
///
/// # Errors
/// Returns an error if decoding, authenticated decryption, or OS string conversion fails.
pub fn decrypt_name_core(encrypted_name_b64: &str, key: &[u8; 32]) -> Result<OsString> {
    // Base64
    let packed = decode_name(encrypted_name_b64)?;

    // check length Nonce 24 + Tag 16
    if packed.len() < NAME_NONCE_LEN + 16 {
        return Err(anyhow!("Invalid encrypted filename format"));
    }

    // split Nonce and content
    let (nonce, ciphertext) = packed.split_at(NAME_NONCE_LEN);

    // init cipher
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_generic = XNonce::try_from(nonce)?;

    // decrypt
    let plain_text = cipher
        .decrypt(&nonce_generic, ciphertext)
        .map_err(|err| anyhow!("Decrypting filename: {err}"))?;

    // to OsString
    match OsStr::from_io_bytes(&plain_text) {
        Some(os_str) => Ok(os_str.into()),
        None => Err(anyhow!("Failed to convert decrypted text to OsStr")),
    }
}

/// Encrypts a single file into the crab stream format.
///
/// # Errors
/// Returns an error if file I/O, key derivation, compression, archiving, or encryption fails.
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
    let key = Key::from(*key_bytes);

    let aead = XChaCha20Poly1305::new(&key);
    let nonce_generic = XChaChaStreamNonce::from(nonce);

    // build encrypt pipeline
    let stream_encryptor = EncryptorBE32::from_aead(aead, &nonce_generic);
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

/// Decrypts a crab stream file into a target directory.
///
/// # Errors
/// Returns an error if file I/O, header parsing, key derivation, decompression,
/// archive validation, or extraction fails.
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
    let key = Key::from(*key_bytes);

    let aead = XChaCha20Poly1305::new(&key);
    let nonce_generic = XChaChaStreamNonce::from(nonce);
    let stream_decryptor = DecryptorBE32::from_aead(aead, &nonce_generic);

    let decrypted_reader = DecryptReader::new(source_file, stream_decryptor)?;

    let gz_decoder = GzDecoder::new(decrypted_reader);

    let mut archive = Archive::new(gz_decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        unpack_archive_entry(&mut entry, dist_dir.as_ref())?;
    }

    Ok(())
}

fn validate_archive_entry_path(entry_path: &Path) -> Result<()> {
    if entry_path.is_absolute() {
        return Err(anyhow!(
            "Illegal archive entry path: {}",
            entry_path.display()
        ));
    }

    if entry_path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(anyhow!(
            "Illegal archive entry path: {}",
            entry_path.display()
        ));
    }

    Ok(())
}

fn validate_archive_entry_type(entry_type: EntryType, entry_path: &Path) -> Result<()> {
    if entry_type.is_file() || entry_type.is_dir() {
        return Ok(());
    }

    let entry_path = entry_path.display();
    Err(anyhow!(
        "Unsupported archive entry type {entry_type:?} for {entry_path}"
    ))
}

fn ensure_directory_exists_in_dist(dist_dir: &Path, dir: &Path) -> Result<()> {
    let mut ancestor = dir;
    let mut dirs_to_create = Vec::<PathBuf>::new();

    while fs::symlink_metadata(ancestor).is_err() {
        dirs_to_create.push(ancestor.to_path_buf());
        ancestor = ancestor.parent().ok_or_else(|| {
            let dir = dir.display();
            anyhow!("Failed to resolve parent path while preparing archive destination {dir}")
        })?;
    }

    for ancestor in dirs_to_create.iter().rev() {
        if let Some(parent) = ancestor.parent() {
            validate_inside_dist(dist_dir, parent)?;
        }

        fs::create_dir(ancestor)
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists
                    && fs::metadata(ancestor).is_ok_and(|metadata| metadata.is_dir())
                {
                    return Ok(());
                }
                Err(error)
            })
            .with_context(|| {
                let ancestor = ancestor.display();
                format!("Failed to create archive destination directory {ancestor}")
            })?;
    }

    Ok(())
}

fn validate_inside_dist(dist_dir: &Path, path: &Path) -> Result<()> {
    let canonical_path = path.canonicalize().with_context(|| {
        let path = path.display();
        format!("Failed to canonicalize archive destination path {path}")
    })?;
    let canonical_dist_dir = dist_dir.canonicalize().with_context(|| {
        let dist_dir = dist_dir.display();
        format!("Failed to canonicalize extraction root {dist_dir}")
    })?;

    if !canonical_path.starts_with(&canonical_dist_dir) {
        let path = path.display();
        anyhow::bail!("Refusing to unpack archive entry outside destination root via {path}");
    }

    Ok(())
}

fn unpack_archive_entry<R: Read>(entry: &mut tar::Entry<R>, dist_dir: &Path) -> Result<()> {
    let entry_path = entry.path()?.into_owned();
    validate_archive_entry_path(&entry_path)?;

    let entry_type = entry.header().entry_type();
    validate_archive_entry_type(entry_type, &entry_path)?;

    let target_path = dist_dir.join(&entry_path);
    if target_path.exists() {
        let target_path = target_path.display();
        return Err(anyhow!(
            "Refusing to overwrite existing path during extraction: {target_path}"
        ));
    }

    if entry_type.is_dir() {
        ensure_directory_exists_in_dist(dist_dir, &target_path).with_context(|| {
            let target_path = target_path.display();
            format!("Failed to create directory for archive entry {target_path}")
        })?;
        return Ok(());
    }

    if let Some(parent) = target_path.parent() {
        ensure_directory_exists_in_dist(dist_dir, parent).with_context(|| {
            let target_path = target_path.display();
            format!("Failed to create parent directory for {target_path}")
        })?;
        validate_inside_dist(dist_dir, parent)?;
    }

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target_path)
        .with_context(|| {
            let target_path = target_path.display();
            format!("Failed to create output file {target_path}")
        })?;

    std::io::copy(entry, &mut output).with_context(|| {
        let target_path = target_path.display();
        format!("Failed to unpack archive entry into {target_path}")
    })?;
    output.flush().with_context(|| {
        let target_path = target_path.display();
        format!("Failed to flush unpacked archive entry {target_path}")
    })?;

    Ok(())
}

/// Builds the encrypted on-disk filename for a file.
///
/// The parent-context argument is retained for source compatibility and is ignored by v3.
///
/// # Errors
/// Returns an error if the source filename is missing or v3 name encryption fails.
pub fn encrypt_file_name(
    source: &Path,
    master_key: &[u8; 32],
    _encrypted_parent_relative: &Path,
) -> Result<PathBuf> {
    let source_file_name = source
        .file_name()
        .ok_or_else(|| anyhow!("Failed to get source file name"))?
        .to_io_bytes_lossy();

    let encrypted_file_name =
        encrypt_name_v3(&source_file_name, master_key, FILE_NAME_CONTEXT_LABEL)?;

    let dir_name = source
        .parent()
        .ok_or_else(|| anyhow!("Failed to get dir name"))?;

    let mut name = OsString::from(encrypted_file_name);
    name.push(".crab");
    Ok(dir_name.join(name))
}

/// Builds the encrypted on-disk directory name for a directory.
///
/// The parent-context argument is retained for source compatibility and is ignored by v3.
///
/// # Errors
/// Returns an error if the source directory name is missing or v3 name encryption fails.
pub fn encrypt_dir_name(
    source: &Path,
    master_key: &[u8; 32],
    _encrypted_parent_relative: &Path,
) -> Result<PathBuf> {
    let source_dir_name = source
        .iter()
        .next_back()
        .ok_or_else(|| anyhow!("Failed to get source dir name"))?
        .to_io_bytes_lossy();

    let encrypted_dir_name = encrypt_name_v3(&source_dir_name, master_key, DIR_NAME_CONTEXT_LABEL)?;

    let dir_name = source
        .parent()
        .ok_or_else(|| anyhow!("Failed to get dir name"))?;

    let mut name = OsString::from(encrypted_dir_name);
    name.push("[crab]");
    Ok(dir_name.join(name))
}

/// Reconstructs the plaintext directory path from an encrypted directory path.
///
/// # Errors
/// Returns an error if the encrypted directory name is malformed or decryption fails.
pub fn decrypt_dir_name(
    source: &Path,
    master_key: &[u8; 32],
    encrypted_parent_relative: &Path,
) -> Result<PathBuf> {
    decrypt_dir_name_with_contexts(
        source,
        master_key,
        &[encrypted_parent_relative.to_path_buf()],
    )
}

/// Reconstructs a plaintext directory path while trying compatible v2 parent contexts.
///
/// v3 and legacy unprefixed names do not depend on these contexts. For v2 names, contexts are
/// attempted in order and authenticated decryption determines the matching one.
///
/// # Errors
/// Returns an error if the encrypted directory name is malformed, no v2 context authenticates,
/// or name decryption fails.
pub fn decrypt_dir_name_with_contexts(
    source: &Path,
    master_key: &[u8; 32],
    encrypted_parent_relatives: &[PathBuf],
) -> Result<PathBuf> {
    let source_dir_str = source
        .iter()
        .next_back()
        .ok_or_else(|| anyhow!("Failed to get source dir name"))?
        .to_str()
        .ok_or_else(|| anyhow!("Failed to get source dir name"))?;

    let encrypted_part = source_dir_str
        .strip_suffix("[crab]")
        .ok_or_else(|| anyhow!("Invalid directory name format"))?;

    let decrypted_os_str = if let Some(versioned_name) = encrypted_part.strip_prefix(NAME_V2_PREFIX)
    {
        let mut first_error = None;
        let mut decrypted = None;

        for encrypted_parent_relative in encrypted_parent_relatives {
            let name_key = derive_name_key(
                master_key,
                encrypted_parent_relative,
                DIR_NAME_CONTEXT_LABEL,
            )?;
            match decrypt_name_core(versioned_name, &name_key) {
                Ok(name) => {
                    decrypted = Some(name);
                    break;
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }

        decrypted.ok_or_else(|| {
            first_error.unwrap_or_else(|| anyhow!("No v2 parent context was provided"))
        })?
    } else if has_v3_name_marker(encrypted_part)? {
        match decrypt_name_v3(encrypted_part, master_key, DIR_NAME_CONTEXT_LABEL) {
            Ok(name) => name,
            Err(v3_error) => match decrypt_name_core(encrypted_part, master_key) {
                // A legacy ciphertext can randomly contain the binary marker.
                Ok(name) => name,
                Err(_) => return Err(v3_error),
            },
        }
    } else {
        decrypt_name_core(encrypted_part, master_key)?
    };

    let dir_name = source
        .parent()
        .ok_or_else(|| anyhow!("Failed to get dir name"))?;

    Ok(dir_name.join(decrypted_os_str))
}

#[cfg(test)]
mod name_format_tests {
    use super::*;

    const TEST_PASSWORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn v2_directory_names_remain_decryptable_with_context_candidates() -> Result<()> {
        let master_key = derive_key(TEST_PASSWORD, NAME_MASTER_SALT)?;
        let correct_context = Path::new("outer[crab]");
        let v2_name_key = derive_name_key(&master_key, correct_context, DIR_NAME_CONTEXT_LABEL)?;
        let encrypted_core = encrypt_name_core(b"legacy-v2", &v2_name_key)?;
        let source = Path::new("root").join(format!("{NAME_V2_PREFIX}{encrypted_core}[crab]"));
        let contexts = vec![
            PathBuf::from("wrong-context"),
            correct_context.to_path_buf(),
        ];

        let decrypted = decrypt_dir_name_with_contexts(&source, &master_key, &contexts)?;

        assert_eq!(decrypted, Path::new("root").join("legacy-v2"));
        Ok(())
    }

    #[test]
    fn legacy_unprefixed_directory_names_remain_decryptable() -> Result<()> {
        let master_key = derive_key(TEST_PASSWORD, NAME_MASTER_SALT)?;
        let encrypted_core = encrypt_name_core(b"legacy", &master_key)?;
        let source = Path::new("root").join(format!("{encrypted_core}[crab]"));

        let decrypted = decrypt_dir_name(&source, &master_key, Path::new("ignored"))?;

        assert_eq!(decrypted, Path::new("root").join("legacy"));
        Ok(())
    }
}
