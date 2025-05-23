use anyhow::Result;
use crab_cryptor::crypt::{decrypt, decrypt_file, encrypt, encrypt_file};
use os_str_bytes::OsStrBytes;

// test token
const TEST_TOKEN: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn test_text_encryption() -> Result<()> {
    let plain_text = b"Hello, world!";
    let encrypted = encrypt(plain_text, TEST_TOKEN)?;
    let decrypted = decrypt(encrypted, TEST_TOKEN)?;

    assert_eq!(decrypted.to_io_bytes(), Some(&plain_text[..]));
    Ok(())
}

#[test]
fn test_file_encryption() -> Result<()> {
    // create a temporary file
    let test_content = b"Test file content for encryption";
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path().join("test.txt");

    // write the test content to the file
    std::fs::write(&temp_path, test_content)?;

    // encrypt the file
    let encrypted_path = temp_dir.path().join("test.enc");
    encrypt_file(&temp_path, &encrypted_path, TEST_TOKEN)?;

    // decrypt the file
    let decrypted_dir = temp_dir.path().join("decrypted");
    std::fs::create_dir(&decrypted_dir)?;
    let decrypted_path = decrypted_dir.join("test.txt");
    decrypt_file(&encrypted_path, &decrypted_path, TEST_TOKEN)?;

    // verify the decrypted content
    let decrypted_content = std::fs::read(&decrypted_path)?;
    assert_eq!(decrypted_content, test_content);

    Ok(())
}

#[test]
fn test_empty_file_encryption() -> Result<()> {
    // create a temporary file
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path().join("empty.txt");
    std::fs::File::create(&temp_path)?;

    // encrypt the file
    let encrypted_path = temp_dir.path().join("empty.enc");
    encrypt_file(&temp_path, &encrypted_path, TEST_TOKEN)?;

    // decrypt the file
    let decrypted_dir = temp_dir.path().join("decrypted");
    std::fs::create_dir(&decrypted_dir)?;
    let decrypted_path = decrypted_dir.join("empty.txt");
    decrypt_file(&encrypted_path, &decrypted_path, TEST_TOKEN)?;

    // verify the decrypted content
    let decrypted_content = std::fs::read(&decrypted_path)?;
    assert!(decrypted_content.is_empty());

    Ok(())
}
