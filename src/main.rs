use anyhow::Result;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use clap::{arg, value_parser, Command};
use crypt::*;
use indicatif::ProgressBar;
use std::ffi::OsStr;
use std::fs::remove_file;
use std::path::PathBuf;
use walkdir::WalkDir;

mod crypt;

fn main() -> Result<()> {
    let matches = Command::new("crab")
        .version("0.1")
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
        let mut hasher = Blake2bVar::new(51).unwrap();
        hasher.update(token.as_bytes());
        let mut buf = [0u8; 51];
        hasher.finalize_variable(&mut buf).unwrap();
        // walk dir
        // generate progress bar
        let walker = WalkDir::new(path).into_iter();
        let total_num_entries = walker.count();
        let bar = ProgressBar::new(total_num_entries.try_into()?);
        for entry in WalkDir::new(path).into_iter() {
            let entry = entry?;
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
                let dist_file_name = get_encrypted_file_name(source, &buf)?;
                // encrypt file
                encrypt_file(source, dist_file_name, &buf)?;
                // remove original file
                remove_file(source)?;
            }
            bar.inc(1);
        }
        bar.finish();
    }
    if let Some(token) = matches.get_one::<String>("decrypt") {
        // extend token
        let mut hasher = Blake2bVar::new(51).unwrap();
        hasher.update(token.as_bytes());
        let mut buf = [0u8; 51];
        hasher.finalize_variable(&mut buf).unwrap();
        // walk dir
        // generate progress bar
        let walker = WalkDir::new(path).into_iter();
        let total_num_entries = walker.count();
        let bar = ProgressBar::new(total_num_entries.try_into()?);
        for entry in WalkDir::new(path).into_iter() {
            let entry = entry?;
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
                let dist_file_name = get_decrypted_file_name(source, &buf)?;
                // decrypt file
                decrypt_file(source, dist_file_name, &buf)?;
                // remove original file
                remove_file(source)?;
            }
            bar.inc(1);
        }
        bar.finish();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;

    use crate::crypt::{decrypt, encrypt};

    #[test]
    fn crypt_test() {
        let token = String::from("crab");
        let mut hasher = Blake2bVar::new(51).unwrap();
        hasher.update(token.as_bytes());
        let mut buf = [0u8; 51];
        hasher.finalize_variable(&mut buf).unwrap();
        let cipher_text = encrypt("plain_text".to_owned(), &buf).unwrap();
        assert_eq!(
            cipher_text,
            "zGEeAhLTe+2D7lkYnP1fLL9e67L8aEqrJ94=".to_owned()
        );
        let plain_text = decrypt("zGEeAhLTe+2D7lkYnP1fLL9e67L8aEqrJ94=".to_owned(), &buf).unwrap();
        assert_eq!(plain_text, "plain_text".to_owned());
    }
}
