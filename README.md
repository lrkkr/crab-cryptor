# crab-cryptor

<p align="center">
	<img src="assets/logo.png" alt="crab-cryptor logo" width="720">
</p>

[![Crates.io](https://img.shields.io/crates/v/crab-cryptor)](https://crates.io/crates/crab-cryptor)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.txt)

A secure, interactive file cryptor written in Rust.

`crab-cryptor` encrypts and decrypts files and directories using XChaCha20-Poly1305 stream encryption, Argon2id key derivation, and gzip compression. It is designed as an interactive CLI for batch directory operations without requiring command-line flags.

## Features

- Authenticated encryption via XChaCha20-Poly1305
- Memory-hard key derivation via Argon2id (64 MiB RAM, 3 iterations)
- File and directory name encryption with URL-safe Base64 output
- Gzip compression before encryption
- Parallel file processing via Rayon
- Operation confirmation before modifying files
- Atomic encrypted file replacement via temporary files and rename
- Path traversal protection during archive extraction
- Symbolic links are skipped instead of being followed
- Passwords and derived keys are zeroized after use

## Install

```bash
cargo install crab-cryptor
```

## Usage

Run `crab` and follow the prompts:

```text
crab v4.1.0
Author: xl_g <lr_kkr@outlook.com>
A secure file cryptor

? Choose function: encrypt
? Work directory: data/
? Encryption password:
Scanning files...
? Will encrypt 12 files and 4 directories in "data/". Continue? (y/N)
```

### Encrypt a directory

```text
crab
? Choose function: encrypt
? Work directory: path/to/dir
? Encryption password:
Scanning files...
? Will encrypt 12 files and 4 directories in "path/to/dir". Continue? (y/N)
```

Encrypted files receive the `.crab` extension. Encrypted directories are renamed to URL-safe Base64 plus the `[crab]` suffix.

### Decrypt a directory

```text
crab
? Choose function: decrypt
? Work directory: path/to/dir
? Decryption password:
Scanning files...
? Will decrypt 12 files and 4 directories in "path/to/dir". Continue? (y/N)
```

During decryption, file contents are restored into the parent directory of each encrypted file. Archive entries are validated before extraction to prevent writing outside the selected directory tree.

## Security Notes

- File contents are encrypted and authenticated.
- File and directory names are obfuscated, but directory encryption state is still represented by the `[crab]` suffix.
- Symlinks are skipped deliberately to avoid accidentally following links outside the selected tree.
- If any item fails during processing, the command exits with an error after reporting the number of failed entries.

## Limitations

- The filename encryption salt is currently a fixed application constant for compatibility.
- The tool is interactive by design and does not currently expose a non-interactive CLI mode.
- Decryption expects files produced by this tool and identified by the `CRABv4` magic header.

## License

MIT — see [LICENSE.txt](LICENSE.txt)

## Reference

- [Rust file encryption](https://kerkour.com/rust-file-encryption)
