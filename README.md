# crab-cryptor

## About

A simple file cryptor written in Rust.

## Notice

### Upgrade to v1.0.0

This project has a breaking change in version v1.0.0.
A key derivation function is used in v1.0.0.
The previous version is not compatible with the current version.
If you want to decrypt the file encrypted by the previous version, please use the previous version.

### Upgrade to v2.0.0

This project has a breaking change in version v2.0.0.
URL-safe base64 encoding without padding is used in v2.0.0.
The previous version is not compatible with the current version.
If you want to decrypt the file encrypted by the previous version, please use the previous version.

## Install

```bash
cargo install crab-cryptor
```

## Getting Started

### Encrypt

```bash
crab
```

```bash
crab v2.0.0
Author: xl_g <lr_kkr@outlook.com>
A file cryptor

> Choose function: encrypt
> Work directory: data
> Encryption token:
```

### Decrypt

```bash
crab
```

```bash
crab v2.0.0
Author: xl_g <lr_kkr@outlook.com>
A file cryptor

> Choose function: decrypt
> Work directory: data
> Encryption token:
```

## License

MIT license

## Reference

- [Rust file encryption](https://kerkour.com/rust-file-encryption)
