use chacha20poly1305::aead::stream::DecryptorBE32;
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

impl<R: Read> DecryptReader<R> {
    pub fn new(mut reader: R, decryptor: DecryptorBE32<XChaCha20Poly1305>) -> Self {
        // init pre read
        let mut first_chunk = vec![0u8; CHUNK_SIZE];
        let mut read_len = 0;

        while read_len < CHUNK_SIZE {
            match reader.read(&mut first_chunk[read_len..]) {
                Ok(0) => break,
                Ok(n) => read_len += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        first_chunk.truncate(read_len);

        Self {
            inner_reader: reader,
            decryptor: Some(decryptor),
            plaintext_buffer: Vec::new(),
            plaintext_pos: 0,
            current_ciphertext: first_chunk,
            finished: false,
        }
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.plaintext_pos < self.plaintext_buffer.len() {
            let available = self.plaintext_buffer.len() - self.plaintext_pos;
            let to_copy = std::cmp::min(available, buf.len());
            buf[..to_copy].copy_from_slice(
                &self.plaintext_buffer[self.plaintext_pos..self.plaintext_pos + to_copy],
            );
            self.plaintext_pos += to_copy;
            return Ok(to_copy);
        }

        if self.finished {
            return Ok(0);
        }

        // read next chunk
        let mut next_chunk = vec![0u8; CHUNK_SIZE];
        let mut read_len = 0;
        while read_len < CHUNK_SIZE {
            match self.inner_reader.read(&mut next_chunk[read_len..]) {
                Ok(0) => break,
                Ok(n) => read_len += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        next_chunk.truncate(read_len);

        if next_chunk.is_empty() {
            // read last chunk
            if let Some(decryptor) = self.decryptor.take() {
                decryptor
                    .decrypt_last_in_place(b"", &mut self.current_ciphertext)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Decrypt last failed: {}", e),
                        )
                    })?;
            } else {
                return Err(io::Error::other("Decryptor logic error: already consumed"));
            }

            self.finished = true;
        } else if let Some(decryptor) = self.decryptor.as_mut() {
            decryptor
                .decrypt_next_in_place(b"", &mut self.current_ciphertext)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Decrypt next failed: {}", e),
                    )
                })?;
        } else {
            return Err(io::Error::other("Decryptor missing unexpectedly"));
        }

        self.plaintext_buffer.clear();
        self.plaintext_buffer
            .extend_from_slice(&self.current_ciphertext);
        self.plaintext_pos = 0;

        self.current_ciphertext = next_chunk;

        self.read(buf)
    }
}
