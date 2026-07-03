use aead_stream::DecryptorBE32;
use chacha20poly1305::XChaCha20Poly1305;
use std::io::{self, Read};

const CHUNK_SIZE: usize = 64 * 1024 + 16; // 64KB Data + 16B Tag

pub struct DecryptReader<R: Read> {
    inner_reader: R,

    decryptor: Option<DecryptorBE32<XChaCha20Poly1305>>,

    plaintext_buffer: Vec<u8>,
    plaintext_pos: usize,
    current_ciphertext: Vec<u8>,
    finished: bool,
}

fn read_ciphertext_chunk<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut read_len = 0;

    while read_len < CHUNK_SIZE {
        let buffer_tail = chunk
            .get_mut(read_len..)
            .ok_or_else(|| io::Error::other("Ciphertext chunk cursor out of bounds"))?;

        match reader.read(buffer_tail) {
            Ok(0) => break,
            Ok(n) => read_len += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }

    chunk.truncate(read_len);
    Ok(chunk)
}

impl<R: Read> DecryptReader<R> {
    /// Creates a streaming decrypt reader and preloads the first ciphertext chunk.
    ///
    /// # Errors
    /// Returns the underlying reader error if the initial ciphertext prefetch fails.
    pub fn new(mut reader: R, decryptor: DecryptorBE32<XChaCha20Poly1305>) -> io::Result<Self> {
        let first_chunk = read_ciphertext_chunk(&mut reader)?;

        Ok(Self {
            inner_reader: reader,
            decryptor: Some(decryptor),
            plaintext_buffer: Vec::new(),
            plaintext_pos: 0,
            current_ciphertext: first_chunk,
            finished: false,
        })
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            if self.plaintext_pos < self.plaintext_buffer.len() {
                let available = self.plaintext_buffer.len() - self.plaintext_pos;
                let to_copy = std::cmp::min(available, buf.len());
                let end = self.plaintext_pos + to_copy;
                let source = self
                    .plaintext_buffer
                    .get(self.plaintext_pos..end)
                    .ok_or_else(|| io::Error::other("Plaintext buffer cursor out of bounds"))?;
                let destination = buf
                    .get_mut(..to_copy)
                    .ok_or_else(|| io::Error::other("Destination buffer cursor out of bounds"))?;
                destination.copy_from_slice(source);
                self.plaintext_pos += to_copy;
                return Ok(to_copy);
            }

            if self.finished {
                return Ok(0);
            }

            let next_chunk = read_ciphertext_chunk(&mut self.inner_reader)?;
            let mut decrypted_chunk = std::mem::take(&mut self.current_ciphertext);

            if next_chunk.is_empty() {
                let decryptor = self
                    .decryptor
                    .take()
                    .ok_or_else(|| io::Error::other("Decryptor logic error: already consumed"))?;

                decryptor
                    .decrypt_last_in_place(b"", &mut decrypted_chunk)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Decrypt last failed: {e}"),
                        )
                    })?;

                self.finished = true;
            } else {
                let decryptor = self
                    .decryptor
                    .as_mut()
                    .ok_or_else(|| io::Error::other("Decryptor missing unexpectedly"))?;

                decryptor
                    .decrypt_next_in_place(b"", &mut decrypted_chunk)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Decrypt next failed: {e}"),
                        )
                    })?;

                self.current_ciphertext = next_chunk;
            }

            self.plaintext_buffer = decrypted_chunk;
            self.plaintext_pos = 0;
        }
    }
}
