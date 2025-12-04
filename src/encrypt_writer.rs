use chacha20poly1305::aead::stream::EncryptorBE32;
use chacha20poly1305::XChaCha20Poly1305;
use std::io::{self, Write};

const BUFFER_LEN: usize = 64 * 1024; // 64 KB

pub struct EncryptWriter<W: Write> {
    inner_writer: W,
    encryptor: EncryptorBE32<XChaCha20Poly1305>,
    buffer: Vec<u8>,
}

impl<W: Write> EncryptWriter<W> {
    pub fn new(writer: W, encryptor: EncryptorBE32<XChaCha20Poly1305>) -> Self {
        Self {
            inner_writer: writer,
            encryptor,
            buffer: Vec::with_capacity(BUFFER_LEN),
        }
    }

    pub fn finish(mut self) -> io::Result<W> {
        // last chunk
        let ciphertext = self
            .encryptor
            .encrypt_last(&self.buffer[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        self.inner_writer.write_all(&ciphertext)?;
        self.inner_writer.flush()?;
        Ok(self.inner_writer)
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        while self.buffer.len() >= BUFFER_LEN {
            let chunk: Vec<u8> = self.buffer.drain(0..BUFFER_LEN).collect();
            // next chunk
            let ciphertext = self
                .encryptor
                .encrypt_next(&chunk[..])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            self.inner_writer.write_all(&ciphertext)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner_writer.flush()
    }
}
