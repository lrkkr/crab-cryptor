use anyhow::Result;
use chacha20poly1305::{
    Key, XChaCha20Poly1305,
    aead::{KeyInit, stream},
};
use crab_cryptor::decrypt_reader::DecryptReader;
use std::io::{self, Read};

struct BrokenReader;

impl Read for BrokenReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("boom"))
    }
}

#[test]
fn test_decrypt_reader_new_propagates_initial_read_error() -> Result<()> {
    let key = Key::from_slice(&[0x33; 32]);
    let aead = XChaCha20Poly1305::new(key);
    let nonce = chacha20poly1305::aead::generic_array::GenericArray::from_slice(&[0x44; 19]);
    let decryptor = stream::DecryptorBE32::from_aead(aead, nonce);

    let Err(error) = DecryptReader::new(BrokenReader, decryptor) else {
        anyhow::bail!("DecryptReader::new should return the underlying read error");
    };

    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(error.to_string().contains("boom"));
    Ok(())
}
