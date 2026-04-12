use anyhow::Result;
use chacha20poly1305::{
    Key, XChaCha20Poly1305,
    aead::{KeyInit, stream},
};
use crab_cryptor::{
    crypt::{MAGIC_HEADER, decrypt_file, derive_key},
    encrypt_writer::EncryptWriter,
};
use flate2::{Compression, write::GzEncoder};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use tar::{Builder, EntryType, Header};

const TEST_PASSWORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 19;

fn write_encrypted_tar_bytes(path: &Path, tar_bytes: &[u8]) -> Result<()> {
    let mut output = File::create(path)?;
    output.write_all(MAGIC_HEADER)?;

    let salt = [0x11; SALT_LEN];
    output.write_all(&salt)?;

    let nonce = [0x22; NONCE_LEN];
    output.write_all(&nonce)?;

    let key_bytes = derive_key(TEST_PASSWORD, &salt)?;
    let key = Key::from_slice(&*key_bytes);
    let aead = XChaCha20Poly1305::new(key);
    let nonce_generic = chacha20poly1305::aead::generic_array::GenericArray::from_slice(&nonce);
    let stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce_generic);
    let encrypted_writer = EncryptWriter::new(output, stream_encryptor);
    let mut gz_encoder = GzEncoder::new(encrypted_writer, Compression::default());

    gz_encoder.write_all(tar_bytes)?;
    let encrypted_writer = gz_encoder.finish()?;
    let mut output = encrypted_writer.finish()?;
    output.flush()?;

    Ok(())
}

fn build_regular_file_tar_bytes(path: &str, contents: &[u8]) -> Result<Vec<u8>> {
    let mut builder = Builder::new(Vec::new());
    let mut header = Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(contents.len() as u64);
    header.set_cksum();
    builder.append_data(&mut header, path, contents)?;
    Ok(builder.into_inner()?)
}

fn build_link_tar_bytes(entry_type: EntryType, path: &str, link_name: &str) -> Result<Vec<u8>> {
    let mut builder = Builder::new(Vec::new());
    let mut header = Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_mode(0o644);
    header.set_size(0);
    header.set_link_name(link_name)?;
    header.set_cksum();
    builder.append_data(&mut header, path, io::empty())?;
    Ok(builder.into_inner()?)
}

fn rewrite_first_header_path(tar_bytes: &mut [u8], new_path: &[u8]) {
    assert!(new_path.len() < 100);

    if let Some(path_field) = tar_bytes.get_mut(..100) {
        path_field.fill(0);
        if let Some(path_prefix) = path_field.get_mut(..new_path.len()) {
            path_prefix.copy_from_slice(new_path);
        }
    }

    if let Some(checksum_field) = tar_bytes.get_mut(148..156) {
        checksum_field.fill(b' ');
    }

    let checksum: u32 = tar_bytes
        .get(..512)
        .map(|header| header.iter().map(|byte| u32::from(*byte)).sum())
        .unwrap_or_default();
    let checksum_field = format!("{checksum:06o}\0 ");
    if let Some(target_checksum_field) = tar_bytes.get_mut(148..156) {
        target_checksum_field.copy_from_slice(checksum_field.as_bytes());
    }
}

#[cfg(unix)]
fn create_dir_link(link_path: &Path, target_path: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target_path, link_path)
}

#[cfg(windows)]
fn create_dir_link(link_path: &Path, target_path: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_dir(target_path, link_path)
}

#[test]
fn test_malicious_parent_dir_entry_is_rejected() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let encrypted_path = temp_dir.path().join("archive.crab");
    let output_dir = temp_dir.path().join("output");
    let outside_path = temp_dir.path().join("payload.txt");

    let mut tar_bytes = build_regular_file_tar_bytes("payload.txt", b"owned")?;
    rewrite_first_header_path(&mut tar_bytes, b"../payload.txt");
    write_encrypted_tar_bytes(&encrypted_path, &tar_bytes)?;
    fs::create_dir(&output_dir)?;

    let error = match decrypt_file(&encrypted_path, &output_dir, TEST_PASSWORD) {
        Ok(()) => anyhow::bail!("expected malicious archive extraction to fail"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("Illegal archive entry path"));
    assert!(!outside_path.exists());
    Ok(())
}

#[test]
fn test_symlink_entry_is_rejected() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let encrypted_path = temp_dir.path().join("symlink.crab");
    let output_dir = temp_dir.path().join("output");

    let tar_bytes = build_link_tar_bytes(EntryType::Symlink, "symlink", "target.txt")?;
    write_encrypted_tar_bytes(&encrypted_path, &tar_bytes)?;
    fs::create_dir(&output_dir)?;

    let error = match decrypt_file(&encrypted_path, &output_dir, TEST_PASSWORD) {
        Ok(()) => anyhow::bail!("expected symlink archive entry to fail"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("Unsupported archive entry type"));
    Ok(())
}

#[test]
fn test_existing_parent_symlink_outside_destination_is_rejected() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let encrypted_path = temp_dir.path().join("escape.crab");
    let output_dir = temp_dir.path().join("output");
    let outside_dir = temp_dir.path().join("outside");
    let linked_dir = output_dir.join("escape");
    let outside_payload = outside_dir.join("payload.txt");

    let tar_bytes = build_regular_file_tar_bytes("escape/payload.txt", b"owned")?;
    write_encrypted_tar_bytes(&encrypted_path, &tar_bytes)?;
    fs::create_dir(&output_dir)?;
    fs::create_dir(&outside_dir)?;

    if let Err(error) = create_dir_link(&linked_dir, &outside_dir) {
        #[cfg(windows)]
        if error.kind() == io::ErrorKind::PermissionDenied {
            eprintln!("skipping symlink containment test: {error}");
            return Ok(());
        }

        return Err(error.into());
    }

    let error = match decrypt_file(&encrypted_path, &output_dir, TEST_PASSWORD) {
        Ok(()) => anyhow::bail!("expected linked parent extraction to fail"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("outside destination root"));
    assert!(!outside_payload.exists());
    Ok(())
}

#[test]
fn test_hard_link_entry_is_rejected() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let encrypted_path = temp_dir.path().join("hardlink.crab");
    let output_dir = temp_dir.path().join("output");

    let tar_bytes = build_link_tar_bytes(EntryType::Link, "hardlink", "target.txt")?;
    write_encrypted_tar_bytes(&encrypted_path, &tar_bytes)?;
    fs::create_dir(&output_dir)?;

    let error = match decrypt_file(&encrypted_path, &output_dir, TEST_PASSWORD) {
        Ok(()) => anyhow::bail!("expected hard-link archive entry to fail"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("Unsupported archive entry type"));
    Ok(())
}
