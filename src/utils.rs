use super::crypt::encrypt;
use anyhow::{anyhow, Result};
use std::path::Path;

pub fn get_dist_file_name(source: &Path, token: &[u8]) -> Result<String> {
    let source_file_name = source
        .file_name()
        .ok_or_else(|| anyhow!("Failed to get source file name"))?
        .to_str()
        .ok_or_else(|| anyhow!("Failed to get source file name"))?
        .to_string();
    // encrypt dist file name
    let encrypted_file_name = encrypt(source_file_name, token)?;
    // get dir name
    let dir_name = source
        .parent()
        .ok_or_else(|| anyhow!("Failed to get dir name"))?;
    Ok(format!(
        "{}.crab",
        dir_name.join(encrypted_file_name).display()
    ))
}
