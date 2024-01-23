use anyhow::Result;
use clap::{arg, value_parser, Command};
use crypt::*;
use indicatif::{ProgressBar, ProgressStyle};
use ring::pbkdf2;
use std::ffi::OsStr;
use std::fs;
use std::num::NonZeroU32;
use std::path::PathBuf;
use walkdir::WalkDir;

mod crypt;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> Result<()> {
    static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;
    const PBKDF2_SALT: &[u8] = b"crab";
    const PBKDF2_KEY_LEN: usize = 51;
    let pbkdf2_iters: NonZeroU32 = NonZeroU32::new(100_000).unwrap();
    let matches = Command::new("crab")
        .version(VERSION)
        .author("xl_g <lr_kkr@outlook.com>")
        .about("A file cryptor")
        .arg(arg!(-p --path <Path> "Selected path").value_parser(value_parser!(PathBuf)))
        .arg(arg!(-e --encrypt <Token> "Encrypt dir").required(false))
        .arg(arg!(-d --decrypt <Token> "Decrypt dir").required(false))
        .get_matches();

    // get path in args
    let path = matches
        .get_one::<PathBuf>("path")
        .expect("path is required");

    if let Some(token) = matches.get_one::<String>("encrypt") {
        // extend token
        let mut buf = vec![0u8; PBKDF2_KEY_LEN];
        pbkdf2::derive(
            PBKDF2_ALG,
            pbkdf2_iters,
            PBKDF2_SALT,
            token.as_bytes(),
            &mut buf,
        );
        // walk dir
        // generate progress bar
        let walker = WalkDir::new(path).into_iter();
        let total_num_entries = walker.count();
        let bar = ProgressBar::new(total_num_entries.try_into()?);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner} {msg}\n{wide_bar} {pos}/{len} in {duration} eta {eta}",
            )
            .unwrap(),
        );
        let entries: Vec<Result<walkdir::DirEntry, walkdir::Error>> =
            WalkDir::new(path).into_iter().collect();
        for entry in entries.into_iter().rev() {
            let entry = entry?;
            let msg = entry.path().iter().last().unwrap();
            bar.set_message(format!("{:?}", msg));
            if entry.metadata()?.is_file() {
                // check if already encrypted
                let source = entry.path();
                let source_extension = source.extension();
                let is_crab = match source_extension {
                    Some(source_extension) => source_extension == OsStr::new("crab"),
                    None => false,
                };
                if is_crab {
                    continue;
                }
                let dist_file_name = encrypt_file_name(source, &buf)?;
                // encrypt file
                encrypt_file(source, dist_file_name, &buf)?;
                // remove original file
                fs::remove_file(source)?;
            } else if entry.metadata()?.is_dir() {
                // check if already encrypted
                let source = entry.path();
                if source == path {
                    continue;
                }
                let source_string = source.to_str();
                let is_crab = match source_string {
                    Some(source_string) => source_string.ends_with("[crab]"),
                    None => false,
                };
                if is_crab {
                    continue;
                }
                let encrypted_dir_name = encrypt_dir_name(source, &buf)?;
                // remove original file
                fs::rename(source, encrypted_dir_name)?;
            }
            bar.inc(1);
        }
        bar.finish_with_message("Done");
    }
    if let Some(token) = matches.get_one::<String>("decrypt") {
        // extend token
        let mut buf = vec![0u8; PBKDF2_KEY_LEN];
        pbkdf2::derive(
            PBKDF2_ALG,
            pbkdf2_iters,
            PBKDF2_SALT,
            token.as_bytes(),
            &mut buf,
        );
        // walk dir
        // generate progress bar
        let walker = WalkDir::new(path).into_iter();
        let total_num_entries = walker.count();
        let bar = ProgressBar::new(total_num_entries.try_into()?);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner} {msg}\n{wide_bar} {pos}/{len} in {duration} eta {eta}",
            )
            .unwrap(),
        );
        let entries: Vec<Result<walkdir::DirEntry, walkdir::Error>> =
            WalkDir::new(path).into_iter().collect();
        for entry in entries.into_iter().rev() {
            let entry = entry?;
            let msg = entry.path().iter().last().unwrap();
            bar.set_message(format!("{:?}", msg));
            if entry.metadata()?.is_file() {
                // check if already encrypted
                let source = entry.path();
                let source_extension = source.extension();
                let is_crab = match source_extension {
                    Some(source_extension) => source_extension == OsStr::new("crab"),
                    None => false,
                };
                if !is_crab {
                    continue;
                }
                let dist_file_name = decrypt_file_name(source, &buf)?;
                // decrypt file
                decrypt_file(source, dist_file_name, &buf)?;
                // remove original file
                fs::remove_file(source)?;
            } else if entry.metadata()?.is_dir() {
                // check if already encrypted
                let source = entry.path();
                if source == path {
                    continue;
                }
                let source_string = source.to_str();
                let is_crab = match source_string {
                    Some(source_string) => source_string.ends_with("[crab]"),
                    None => false,
                };
                if !is_crab {
                    continue;
                }
                let decrypted_dir_name = decrypt_dir_name(source, &buf)?;
                // remove original file
                fs::rename(source, decrypted_dir_name)?;
            }
            bar.inc(1);
        }
        bar.finish_with_message("Done");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::crypt::{decrypt, encrypt};
    use ring::pbkdf2;
    use std::num::NonZeroU32;

    #[test]
    fn crypt_test() {
        static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;
        const PBKDF2_SALT: &[u8] = b"crab";
        const PBKDF2_KEY_LEN: usize = 51;
        let pbkdf2_iters: NonZeroU32 = NonZeroU32::new(100_000).unwrap();
        let token = String::from("crab");
        let mut buf = vec![0u8; PBKDF2_KEY_LEN];
        pbkdf2::derive(
            PBKDF2_ALG,
            pbkdf2_iters,
            PBKDF2_SALT,
            token.as_bytes(),
            &mut buf,
        );
        let cipher_text = encrypt("plain_text".to_owned(), &buf).unwrap();
        assert_eq!(
            cipher_text,
            "MF8gUHeKK45ZVNknudk2YLjFl5j3F82xHDI=".to_owned()
        );
        let plain_text = decrypt("MF8gUHeKK45ZVNknudk2YLjFl5j3F82xHDI=".to_owned(), &buf).unwrap();
        assert_eq!(plain_text, "plain_text".to_owned());
    }
}
