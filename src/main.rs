use crate::crypt::{
    decrypt_dir_name, decrypt_file, derive_key, encrypt_dir_name, encrypt_file, encrypt_file_name,
    MAGIC_HEADER,
};
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{Confirm, Password, Select, Text};
use rayon::prelude::*;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::{DirEntry, WalkDir};
use zeroize::Zeroize;

mod crypt;
mod decrypt_reader;
mod encrypt_writer;

const VERSION: &str = env!("CARGO_PKG_VERSION");
// Salt for encrypt filename and dirname
const FILENAME_SALT: &[u8] = b"CrabFileNameSalt";

#[derive(PartialEq, Clone, Copy)]
enum Mode {
    Encrypt,
    Decrypt,
}

fn main() -> Result<()> {
    // Print Banner
    println!("crab v{}", VERSION);
    println!("Author: xl_g <lr_kkr@outlook.com>");
    println!("A secure file cryptor");
    println!();

    // Select Function
    let functions = vec!["encrypt", "decrypt"];
    let mode_str = Select::new("Choose function:", functions).prompt()?;
    let mode = if mode_str == "encrypt" {
        Mode::Encrypt
    } else {
        Mode::Decrypt
    };

    // Get Path
    let path_input = Text::new("Work directory:").prompt()?;
    let work_path = Path::new(&path_input);

    if !work_path.exists() {
        println!("Invalid path: path does not exist");
        return Ok(());
    }

    // Get Password & Derive Filename Key
    let prompt = if mode == Mode::Encrypt {
        "Encryption password:"
    } else {
        "Decryption password:"
    };
    let mut password = Password::new(prompt).prompt()?;

    // Derive Key for encrypt filename
    let filename_key = derive_key(&password, FILENAME_SALT)?;

    // Collect Entries
    println!("Scanning files...");
    let walker = WalkDir::new(work_path).into_iter();
    let entries: Vec<DirEntry> = walker.filter_map(|e| e.ok()).collect();

    // Split files and directories
    // Files can be processed in parallel. Dirs must be sequential to avoid path errors.
    let (files, dirs): (Vec<_>, Vec<_>) =
        entries.into_iter().partition(|e| e.file_type().is_file());

    // Confirm operation before proceeding
    let action = if mode == Mode::Encrypt {
        "encrypt"
    } else {
        "decrypt"
    };
    let confirmed = Confirm::new(&format!(
        "Will {} {} files and {} directories in {:?}. Continue?",
        action,
        files.len(),
        dirs.len(),
        work_path
    ))
    .with_default(false)
    .prompt()?;

    if !confirmed {
        password.zeroize();
        println!("Operation cancelled.");
        return Ok(());
    }

    // Setup Progress Bar
    let total_num_entries = files.len() + dirs.len();
    let bar = ProgressBar::new(total_num_entries.try_into()?);
    bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta}) \n{msg}",
        )
        .unwrap()
        .progress_chars("#>-"),
    );

    let error_count = AtomicUsize::new(0);

    // Process Files in Parallel (Heavy CPU task)
    files.par_iter().for_each(|entry| {
        let path = entry.path();

        // Update progress bar (thread-safe)
        if let Some(name) = path.file_name() {
            bar.set_message(format!("Processing: {}", name.to_string_lossy()));
        }

        if let Err(e) = process_entry(path, mode, &password, &filename_key, work_path) {
            bar.println(format!("Error processing {:?}: {}", path, e));
            error_count.fetch_add(1, Ordering::Relaxed);
        }
        bar.inc(1);
    });

    // Process Directories Sequentially (Metadata task)
    // Must be reversed (.rev()) to process children before parents
    for entry in dirs.into_iter().rev() {
        let path = entry.path();

        if let Some(name) = path.file_name() {
            bar.set_message(format!("Renaming: {}", name.to_string_lossy()));
        }

        if let Err(e) = process_entry(path, mode, &password, &filename_key, work_path) {
            bar.println(format!("Error processing dir {:?}: {}", path, e));
            error_count.fetch_add(1, Ordering::Relaxed);
        }
        bar.inc(1);
    }

    let errors = error_count.load(Ordering::Relaxed);
    if errors > 0 {
        bar.finish_with_message(format!("Done with {} error(s).", errors));
    } else {
        bar.finish_with_message("All Done!");
    }

    password.zeroize();

    if errors > 0 {
        anyhow::bail!("{} file(s) failed to process", errors);
    }

    Ok(())
}

/// Core process approach
fn process_entry(
    path: &Path,
    mode: Mode,
    password: &str,
    filename_key: &[u8; 32],
    root_path: &Path,
) -> Result<()> {
    // Skip root path
    if path == root_path {
        return Ok(());
    }

    // Use symlink_metadata to avoid following symlinks
    let metadata = match path.symlink_metadata() {
        Ok(m) => m,
        Err(_) => return Ok(()), // File might be gone or inaccessible
    };

    // Skip symlinks
    if metadata.is_symlink() {
        return Ok(());
    }

    if metadata.is_file() {
        // Process file
        let is_encrypted = is_file_encrypted(path);

        match mode {
            Mode::Encrypt => {
                // Skip already encrypted
                if is_encrypted {
                    return Ok(());
                }

                // Generate encrypt filename
                let dist_path = encrypt_file_name(path, filename_key)?;
                let tmp_path = dist_path.with_extension("crab.tmp");

                // Encrypt to temp file first, then rename for atomicity
                encrypt_file(path, &tmp_path, password)?;
                fs::rename(&tmp_path, &dist_path)?;

                // Delete original file
                fs::remove_file(path)?;
            }
            Mode::Decrypt => {
                // Skip non-encrypted
                if !is_encrypted {
                    return Ok(());
                }

                // Decrypt logic: extract to parent dir
                // Tar archive restores original filename
                let output_dir = path.parent().unwrap_or(Path::new("."));

                // Decrypt content
                decrypt_file(path, output_dir, password)?;

                // Delete encrypted file
                fs::remove_file(path)?;
            }
        }
    } else if metadata.is_dir() {
        // Process dir (Rename only)
        let path_str = path.to_string_lossy();
        let is_crab_dir = path_str.ends_with("[crab]");

        match mode {
            Mode::Encrypt => {
                if is_crab_dir {
                    return Ok(());
                }
                let encrypted_dir_name = encrypt_dir_name(path, filename_key)?;
                fs::rename(path, &encrypted_dir_name)?;
            }
            Mode::Decrypt => {
                if !is_crab_dir {
                    return Ok(());
                }
                let decrypted_dir_name = decrypt_dir_name(path, filename_key)?;
                fs::rename(path, &decrypted_dir_name)?;
            }
        }
    }

    Ok(())
}

/// Check if already encrypted by reading header
fn is_file_encrypted(path: &Path) -> bool {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut buffer = vec![0u8; MAGIC_HEADER.len()];
    match file.read_exact(&mut buffer) {
        Ok(_) => buffer == MAGIC_HEADER,
        Err(_) => false,
    }
}
