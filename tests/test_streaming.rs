use aead_stream::{DecryptorBE32, EncryptorBE32, Nonce, StreamBE32};
use anyhow::Result;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use crab_cryptor::{decrypt_reader::DecryptReader, encrypt_writer::EncryptWriter};
use std::io::{self, Read, Write};

struct BrokenReader;

impl Read for BrokenReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("boom"))
    }
}

#[test]
fn test_decrypt_reader_new_propagates_initial_read_error() -> Result<()> {
    let key = Key::from([0x33; 32]);
    let aead = XChaCha20Poly1305::new(&key);
    let nonce = Nonce::<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>::from([0x44; 19]);
    let decryptor = DecryptorBE32::from_aead(aead, &nonce);

    let Err(error) = DecryptReader::new(BrokenReader, decryptor) else {
        anyhow::bail!("DecryptReader::new should return the underlying read error");
    };

    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(error.to_string().contains("boom"));
    Ok(())
}

#[test]
fn test_decrypt_reader_reads_full_chunk_in_small_pieces() -> Result<()> {
    let key = Key::from([0x33; 32]);
    let nonce = Nonce::<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>::from([0x44; 19]);
    let encryptor = EncryptorBE32::from_aead(XChaCha20Poly1305::new(&key), &nonce);
    let decryptor = DecryptorBE32::from_aead(XChaCha20Poly1305::new(&key), &nonce);
    let plaintext: Vec<_> = (0..=250_u8).cycle().take(64 * 1024).collect();
    let mut writer = EncryptWriter::new(Vec::new(), encryptor);
    writer.write_all(&plaintext)?;
    let ciphertext = writer.finish()?;
    let mut reader = DecryptReader::new(ciphertext.as_slice(), decryptor)?;

    let mut output = vec![0; plaintext.len()];
    for chunk in output.chunks_mut(1023) {
        reader.read_exact(chunk)?;
    }
    assert_eq!(output, plaintext);
    assert_eq!(reader.read(&mut [0])?, 0);
    Ok(())
}
