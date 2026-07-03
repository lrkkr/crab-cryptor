use aead_stream::EncryptorBE32;
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

    fn write_encrypted_chunk(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let mut ciphertext = plaintext.to_vec();
        self.encryptor
            .encrypt_next_in_place(b"", &mut ciphertext)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        self.inner_writer.write_all(&ciphertext)
    }

    /// Finalizes the stream and flushes the trailing ciphertext chunk.
    ///
    /// # Errors
    /// Returns an error if final chunk encryption or the final write/flush fails.
    pub fn finish(mut self) -> io::Result<W> {
        // last chunk
        self.encryptor
            .encrypt_last_in_place(b"", &mut self.buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        self.inner_writer.write_all(&self.buffer)?;
        self.inner_writer.flush()?;
        Ok(self.inner_writer)
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut remaining = buf;

        if !self.buffer.is_empty() {
            let to_fill = (BUFFER_LEN - self.buffer.len()).min(remaining.len());
            let (prefix, suffix) = remaining
                .split_at_checked(to_fill)
                .ok_or_else(|| io::Error::other("Plaintext buffer cursor out of bounds"))?;
            self.buffer.extend_from_slice(prefix);
            remaining = suffix;

            if self.buffer.len() == BUFFER_LEN {
                let chunk = std::mem::take(&mut self.buffer);
                self.write_encrypted_chunk(&chunk)?;
                self.buffer = Vec::with_capacity(BUFFER_LEN);
            }
        }

        while remaining.len() >= BUFFER_LEN {
            let (chunk, suffix) = remaining
                .split_at_checked(BUFFER_LEN)
                .ok_or_else(|| io::Error::other("Chunk split cursor out of bounds"))?;
            self.write_encrypted_chunk(chunk)?;
            remaining = suffix;
        }

        if !remaining.is_empty() {
            self.buffer.extend_from_slice(remaining);
        }

        Ok(buf.len())
    }

    /// Note: `flush()` only flushes the underlying writer. Buffered plaintext
    /// cannot be partially encrypted due to AEAD chunk size requirements.
    /// Call `finish()` to finalize encryption and flush all remaining data.
    fn flush(&mut self) -> io::Result<()> {
        self.inner_writer.flush()
    }
}
