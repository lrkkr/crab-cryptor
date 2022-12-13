use anyhow::Result;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use clap::{arg, Command};
use crypt::decrypt_file;
use indicatif::ProgressBar;
use utils::get_dist_file_name;
use walkdir::WalkDir;

mod crypt;
mod utils;

fn main() -> Result<()> {
    let matches = Command::new("crab")
        .version("0.1")
        .author("xl_g <lr_kkr@outlook.com>")
        .about("A file cryptor")
        .arg(arg!(-e --encrypt <Token> "Encrypt dir").required(false))
        .arg(arg!(-d --decrypt <Token> "Decrypt dir").required(false))
        .get_matches();
    if let Some(token) = matches.get_one::<String>("encrypt") {
        // extend token
        let mut hasher = Blake2bVar::new(51).unwrap();
        hasher.update(token.as_bytes());
        let mut buf = [0u8; 51];
        hasher.finalize_variable(&mut buf).unwrap();
        // walk dir
        // generate progress bar
        let walker = WalkDir::new(".").into_iter();
        let total_num_entries = walker.count();
        let bar = ProgressBar::new(total_num_entries.try_into()?);
        for entry in WalkDir::new(".").into_iter() {
            let entry = entry?;
            if entry.metadata()?.is_file() {
                // check if already encrypted
                let source = entry.path();
                let source_extension = source.extension();
                let is_crab = match source_extension {
                    Some(source_extension) => source_extension == "crab",
                    None => false,
                };
                if is_crab {
                    continue;
                }
                let dist_file_name = get_dist_file_name(source, &buf)?;
                println!("{}", dist_file_name);
            }
            bar.inc(1);
        }
        bar.finish();
        // encrypt_file("test.txt", "test.txt.crab", &buf)?;
    }
    if let Some(token) = matches.get_one::<String>("decrypt") {
        // extend token
        let mut hasher = Blake2bVar::new(51).unwrap();
        hasher.update(token.as_bytes());
        let mut buf = [0u8; 51];
        hasher.finalize_variable(&mut buf).unwrap();
        // walk dir
        decrypt_file("test.txt.crab", "test.txt", &buf)?;
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
