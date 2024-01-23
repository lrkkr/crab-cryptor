# crab-cryptor

## About

A simple file cryptor written in Rust.

## Notice

This project has a breaking change in version v1.0.0.
A key derivation function is used in v1.0.0.
The previous version is not compatible with the current version.
If you want to decrypt the file encrypted by the previous version, please use the previous version.

## Install

```bash
cargo install crab-cryptor
```

## Getting Started

### Encrypt

```bash
crab -e superKey -p path/to/
```

### Decrypt

```bash
crab -d superKey -p path/to/
```

## License

MIT license

## Reference

- [Rust file encryption](https://kerkour.com/rust-file-encryption)
