use anyhow::Result;
use crab_cryptor::crypt::{
    decrypt_file, decrypt_name_core, derive_key, encrypt_file, encrypt_name_core,
};
use os_str_bytes::OsStrBytes;
use std::fs;

const TEST_PASSWORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const WRONG_PASSWORD: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const TEST_FILENAME_SALT: &[u8] = b"crabTestSalt";
const LARGE_FILE_LEN: usize = 64 * 1024 * 4 + 321;

#[test]
fn test_text_encryption() -> Result<()> {
    let filename_key = derive_key(TEST_PASSWORD, TEST_FILENAME_SALT)?;
    let plain_text = b"Hello, world!";
    let encrypted = encrypt_name_core(plain_text, &filename_key)?;
    let decrypted = decrypt_name_core(&encrypted, &filename_key)?;

    assert_eq!(decrypted.to_io_bytes(), Some(&plain_text[..]));
    Ok(())
}

#[test]
fn test_file_encryption() -> Result<()> {
    let test_content = b"Test file content for encryption";
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path().join("test.txt");

    fs::write(&temp_path, test_content)?;

    let encrypted_path = temp_dir.path().join("test.enc");
    encrypt_file(&temp_path, &encrypted_path, TEST_PASSWORD)?;

    let decrypted_dir = temp_dir.path().join("decrypted");
    fs::create_dir(&decrypted_dir)?;
    let decrypted_path = decrypted_dir.join("test.txt");
    decrypt_file(&encrypted_path, &decrypted_dir, TEST_PASSWORD)?;

    let decrypted_content = fs::read(&decrypted_path)?;
    assert_eq!(decrypted_content, test_content);

    Ok(())
}

#[test]
fn test_empty_file_encryption() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path().join("empty.txt");
    fs::File::create(&temp_path)?;

    let encrypted_path = temp_dir.path().join("empty.enc");
    encrypt_file(&temp_path, &encrypted_path, TEST_PASSWORD)?;

    let decrypted_dir = temp_dir.path().join("decrypted");
    fs::create_dir(&decrypted_dir)?;
    let decrypted_path = decrypted_dir.join("empty.txt");
    decrypt_file(&encrypted_path, &decrypted_dir, TEST_PASSWORD)?;

    let decrypted_content = fs::read(&decrypted_path)?;
    assert!(decrypted_content.is_empty());

    Ok(())
}

#[test]
fn test_wrong_password_does_not_create_output() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path().join("secret.txt");
    let encrypted_path = temp_dir.path().join("secret.enc");
    let decrypted_dir = temp_dir.path().join("decrypted");
    let decrypted_path = decrypted_dir.join("secret.txt");

    fs::write(&temp_path, b"top secret")?;
    encrypt_file(&temp_path, &encrypted_path, TEST_PASSWORD)?;
    fs::create_dir(&decrypted_dir)?;

    let error = match decrypt_file(&encrypted_path, &decrypted_dir, WRONG_PASSWORD) {
        Ok(()) => anyhow::bail!("expected decryption with the wrong password to fail"),
        Err(error) => error,
    };

    assert!(!decrypted_path.exists());
    assert!(!error.to_string().is_empty());
    Ok(())
}

#[test]
fn test_corrupted_ciphertext_is_rejected() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path().join("corrupt.txt");
    let encrypted_path = temp_dir.path().join("corrupt.enc");
    let decrypted_dir = temp_dir.path().join("decrypted");

    fs::write(&temp_path, b"corrupt me")?;
    encrypt_file(&temp_path, &encrypted_path, TEST_PASSWORD)?;

    let mut encrypted_bytes = fs::read(&encrypted_path)?;
    let Some(last_byte) = encrypted_bytes.last_mut() else {
        anyhow::bail!("encrypted file should not be empty");
    };
    *last_byte ^= 0x5a;
    fs::write(&encrypted_path, encrypted_bytes)?;

    fs::create_dir(&decrypted_dir)?;
    assert!(decrypt_file(&encrypted_path, &decrypted_dir, TEST_PASSWORD).is_err());

    Ok(())
}

#[test]
fn test_decrypt_rejects_existing_target_path() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path().join("test.txt");
    let encrypted_path = temp_dir.path().join("test.enc");
    let decrypted_dir = temp_dir.path().join("decrypted");
    let decrypted_path = decrypted_dir.join("test.txt");

    fs::write(&temp_path, b"fresh data")?;
    encrypt_file(&temp_path, &encrypted_path, TEST_PASSWORD)?;

    fs::create_dir(&decrypted_dir)?;
    fs::write(&decrypted_path, b"keep original")?;

    let error = match decrypt_file(&encrypted_path, &decrypted_dir, TEST_PASSWORD) {
        Ok(()) => anyhow::bail!("expected an overwrite-protection failure"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("overwrite"));
    assert_eq!(fs::read(&decrypted_path)?, b"keep original");
    Ok(())
}

#[test]
fn test_large_file_multiple_chunks_round_trip() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path().join("large.bin");
    let encrypted_path = temp_dir.path().join("large.enc");
    let decrypted_dir = temp_dir.path().join("decrypted");
    let decrypted_path = decrypted_dir.join("large.bin");
    let pattern: Vec<u8> = (0_u8..251_u8).collect();
    let test_content: Vec<u8> = pattern
        .iter()
        .copied()
        .cycle()
        .take(LARGE_FILE_LEN)
        .collect();

    fs::write(&temp_path, &test_content)?;
    encrypt_file(&temp_path, &encrypted_path, TEST_PASSWORD)?;

    fs::create_dir(&decrypted_dir)?;
    decrypt_file(&encrypted_path, &decrypted_dir, TEST_PASSWORD)?;

    let decrypted_content = fs::read(&decrypted_path)?;
    assert_eq!(decrypted_content, test_content);

    Ok(())
}
