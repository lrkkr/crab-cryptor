use crate::crypt::{
    MAGIC_HEADER, MIN_ENCRYPTED_FILE_LEN, NAME_MASTER_SALT, decrypt_dir_name, decrypt_file,
    derive_key, encrypt_dir_name, encrypt_file, encrypt_file_name,
};
use anyhow::{Context, Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{Confirm, Password, Select, Text};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::WalkDir;
use zeroize::Zeroizing;

mod crypt;
mod decrypt_reader;
mod encrypt_writer;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(PartialEq, Clone, Copy)]
enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(Default)]
struct ScanSnapshot {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
}

enum FilePlanKind {
    Encrypt { target_path: PathBuf },
    Decrypt { output_dir: PathBuf },
}

struct FilePlan {
    source_path: PathBuf,
    kind: FilePlanKind,
}

struct DirRenamePlan {
    source_path: PathBuf,
    target_path: PathBuf,
    depth: usize,
}

struct OperationPlan {
    file_plans: Vec<FilePlan>,
    dir_plans: Vec<DirRenamePlan>,
}

struct ExecutionSummary {
    file_errors: usize,
    dir_errors: usize,
}

fn main() -> Result<()> {
    println!("crab v{VERSION}");
    println!("Author: xl_g <lr_kkr@outlook.com>");
    println!("A secure file cryptor");
    println!();

    let functions = vec!["encrypt", "decrypt"];
    let mode_str = Select::new("Choose function:", functions).prompt()?;
    let mode = if mode_str == "encrypt" {
        Mode::Encrypt
    } else {
        Mode::Decrypt
    };

    let path_input = Text::new("Work directory:").prompt()?;
    let work_path = Path::new(&path_input);

    if !work_path.exists() {
        println!("Invalid path: path does not exist");
        return Ok(());
    }

    let prompt = if mode == Mode::Encrypt {
        "Encryption password:"
    } else {
        "Decryption password:"
    };
    let password = Zeroizing::new(Password::new(prompt).prompt()?);

    println!("Scanning files...");
    let snapshot = collect_snapshot(work_path);

    let operation_plan = {
        let name_master_key = derive_key(password.as_str(), NAME_MASTER_SALT)?;
        build_operation_plan(mode, work_path, &snapshot, &name_master_key)?
    };

    let action = if mode == Mode::Encrypt {
        "encrypt"
    } else {
        "decrypt"
    };
    let confirmed = Confirm::new(&format!(
        "Will {action} {} files and {} directories in {}. Continue?",
        operation_plan.file_plans.len(),
        operation_plan.dir_plans.len(),
        work_path.display()
    ))
    .with_default(false)
    .prompt()?;

    if !confirmed {
        println!("Operation cancelled.");
        return Ok(());
    }

    let total_num_entries = operation_plan.file_plans.len() + operation_plan.dir_plans.len();
    let bar = ProgressBar::new(total_num_entries.try_into()?);
    let style = ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta}) \n{msg}",
    )?
    .progress_chars("#>-");
    bar.set_style(style);

    let summary = execute_operation_plan(&operation_plan, mode, password.as_str(), &bar);
    let total_errors = summary.file_errors + summary.dir_errors;

    if total_errors > 0 {
        bar.finish_with_message(format!(
            "Done with {} file error(s) and {} directory error(s).",
            summary.file_errors, summary.dir_errors
        ));
    } else {
        bar.finish_with_message("All Done!");
    }

    if summary.dir_errors > 0 {
        anyhow::bail!(
            "{total_errors} item(s) failed. Some files may already have been processed and some directories may remain unrenamed; review the reported source/target paths."
        );
    }

    if total_errors > 0 {
        anyhow::bail!("{total_errors} file(s) failed to process");
    }

    Ok(())
}

fn collect_snapshot(root_path: &Path) -> ScanSnapshot {
    let mut snapshot = ScanSnapshot::default();

    for entry in WalkDir::new(root_path)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();
        if path == root_path {
            continue;
        }

        let file_type = entry.file_type();
        if file_type.is_symlink() {
            continue;
        }

        if file_type.is_file() {
            snapshot.files.push(path.to_path_buf());
        } else if file_type.is_dir() {
            snapshot.dirs.push(path.to_path_buf());
        }
    }

    snapshot
}

fn build_operation_plan(
    mode: Mode,
    root_path: &Path,
    snapshot: &ScanSnapshot,
    name_master_key: &[u8; 32],
) -> Result<OperationPlan> {
    match mode {
        Mode::Encrypt => build_encrypt_operation_plan(root_path, snapshot, name_master_key),
        Mode::Decrypt => build_decrypt_operation_plan(root_path, snapshot, name_master_key),
    }
}

fn build_encrypt_operation_plan(
    root_path: &Path,
    snapshot: &ScanSnapshot,
    name_master_key: &[u8; 32],
) -> Result<OperationPlan> {
    let mut dir_inputs = snapshot.dirs.clone();
    dir_inputs.sort_by_key(|path| path_depth(path));

    let mut encrypted_relative_dirs = HashMap::<PathBuf, PathBuf>::new();
    let mut dir_plans = Vec::new();

    for source_path in dir_inputs {
        let relative_path = relative_to_root(&source_path, root_path)?;
        let parent_relative = relative_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let encrypted_parent_relative = encrypted_relative_dirs
            .get(&parent_relative)
            .cloned()
            .unwrap_or(parent_relative.clone());

        if is_crab_dir(&source_path) {
            encrypted_relative_dirs.insert(relative_path.clone(), relative_path);
            continue;
        }

        let target_path =
            encrypt_dir_name(&source_path, name_master_key, &encrypted_parent_relative)
                .with_context(|| {
                    let source_path = source_path.display();
                    format!("Failed to plan encrypted directory name for {source_path}")
                })?;

        let encrypted_name = target_path
            .file_name()
            .map(OsStr::to_os_string)
            .ok_or_else(|| {
                let source_path = source_path.display();
                anyhow!("Failed to get encrypted directory name for {source_path}")
            })?;
        let encrypted_relative =
            append_relative_component(&encrypted_parent_relative, &encrypted_name);

        dir_plans.push(DirRenamePlan {
            depth: path_depth(&relative_path),
            source_path,
            target_path,
        });
        encrypted_relative_dirs.insert(relative_path, encrypted_relative);
    }

    let mut file_plans = Vec::new();
    for source_path in &snapshot.files {
        if is_file_encrypted(source_path) {
            continue;
        }

        let parent_relative = relative_parent_to_root(source_path, root_path)?;
        let encrypted_parent_relative = encrypted_relative_dirs
            .get(&parent_relative)
            .cloned()
            .unwrap_or(parent_relative.clone());
        let target_path =
            encrypt_file_name(source_path, name_master_key, &encrypted_parent_relative)
                .with_context(|| {
                    let source_path = source_path.display();
                    format!("Failed to plan encrypted file name for {source_path}")
                })?;

        file_plans.push(FilePlan {
            source_path: source_path.clone(),
            kind: FilePlanKind::Encrypt { target_path },
        });
    }

    validate_dir_rename_plans(&dir_plans)?;
    dir_plans.sort_by(|left, right| {
        right
            .depth
            .cmp(&left.depth)
            .then_with(|| left.source_path.cmp(&right.source_path))
    });

    Ok(OperationPlan {
        file_plans,
        dir_plans,
    })
}

fn build_decrypt_operation_plan(
    root_path: &Path,
    snapshot: &ScanSnapshot,
    name_master_key: &[u8; 32],
) -> Result<OperationPlan> {
    let mut file_plans = Vec::new();
    for source_path in &snapshot.files {
        if !is_file_encrypted(source_path) {
            continue;
        }

        let output_dir = source_path
            .parent()
            .map_or_else(|| root_path.to_path_buf(), Path::to_path_buf);

        file_plans.push(FilePlan {
            source_path: source_path.clone(),
            kind: FilePlanKind::Decrypt { output_dir },
        });
    }

    let mut dir_plans = Vec::new();
    for source_path in &snapshot.dirs {
        if !is_crab_dir(source_path) {
            continue;
        }

        let relative_path = relative_to_root(source_path, root_path)?;
        let parent_relative = relative_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let target_path = decrypt_dir_name(source_path, name_master_key, &parent_relative)
            .with_context(|| {
                let source_path = source_path.display();
                format!("Failed to plan decrypted directory name for {source_path}")
            })?;

        dir_plans.push(DirRenamePlan {
            depth: path_depth(&relative_path),
            source_path: source_path.clone(),
            target_path,
        });
    }

    validate_dir_rename_plans(&dir_plans)?;
    dir_plans.sort_by(|left, right| {
        right
            .depth
            .cmp(&left.depth)
            .then_with(|| left.source_path.cmp(&right.source_path))
    });

    Ok(OperationPlan {
        file_plans,
        dir_plans,
    })
}

fn execute_operation_plan(
    operation_plan: &OperationPlan,
    mode: Mode,
    password: &str,
    bar: &ProgressBar,
) -> ExecutionSummary {
    // Files keep the directory topology stable, so they can run in parallel first.
    // Directory renames depend on parent-child ordering, so they execute serially from deepest to shallowest.
    let file_errors = execute_file_plans(&operation_plan.file_plans, mode, password, bar);
    let dir_errors = execute_dir_rename_plans(&operation_plan.dir_plans, bar);

    ExecutionSummary {
        file_errors,
        dir_errors,
    }
}

fn execute_file_plans(
    file_plans: &[FilePlan],
    mode: Mode,
    password: &str,
    bar: &ProgressBar,
) -> usize {
    let error_count = AtomicUsize::new(0);

    file_plans.par_iter().for_each(|plan| {
        if let Some(name) = plan.source_path.file_name() {
            let name = name.to_string_lossy();
            bar.set_message(format!("Processing: {name}"));
        }

        if let Err(error) = execute_file_plan(plan, mode, password) {
            let path = plan.source_path.display();
            bar.println(format!("Error processing {path}: {error}"));
            error_count.fetch_add(1, Ordering::Relaxed);
        }

        bar.inc(1);
    });

    error_count.load(Ordering::Relaxed)
}

fn execute_file_plan(plan: &FilePlan, mode: Mode, password: &str) -> Result<()> {
    match (&plan.kind, mode) {
        (FilePlanKind::Encrypt { target_path }, Mode::Encrypt) => {
            if target_path.exists() {
                let target_path = target_path.display();
                anyhow::bail!("Refusing to overwrite existing encrypted file {target_path}");
            }

            let tmp_path = target_path.with_extension("crab.tmp");
            if tmp_path.exists() {
                let tmp_path = tmp_path.display();
                anyhow::bail!("Temporary file already exists: {tmp_path}");
            }

            let encrypt_result =
                encrypt_file(&plan.source_path, &tmp_path, password).with_context(|| {
                    let source_path = plan.source_path.display();
                    let tmp_path = tmp_path.display();
                    format!("Failed to encrypt file {source_path} into temporary output {tmp_path}")
                });

            if let Err(error) = encrypt_result {
                let _ = fs::remove_file(&tmp_path);
                return Err(error);
            }

            if let Err(error) = fs::rename(&tmp_path, target_path).with_context(|| {
                let tmp_path = tmp_path.display();
                let target_path = target_path.display();
                format!("Failed to rename encrypted temporary file {tmp_path} to {target_path}")
            }) {
                let _ = fs::remove_file(&tmp_path);
                return Err(error);
            }

            fs::remove_file(&plan.source_path).with_context(|| {
                let source_path = plan.source_path.display();
                format!("Failed to remove original file {source_path}")
            })?;
        }
        (FilePlanKind::Decrypt { output_dir }, Mode::Decrypt) => {
            decrypt_file(&plan.source_path, output_dir, password).with_context(|| {
                let source_path = plan.source_path.display();
                let output_dir = output_dir.display();
                format!("Failed to decrypt file {source_path} into {output_dir}")
            })?;

            fs::remove_file(&plan.source_path).with_context(|| {
                let source_path = plan.source_path.display();
                format!("Failed to remove encrypted file {source_path}")
            })?;
        }
        _ => return Err(anyhow!("Mismatched file plan for requested mode")),
    }

    Ok(())
}

fn execute_dir_rename_plans(dir_plans: &[DirRenamePlan], bar: &ProgressBar) -> usize {
    let mut error_count = 0;

    for plan in dir_plans {
        if let Some(name) = plan.source_path.file_name() {
            let name = name.to_string_lossy();
            bar.set_message(format!("Renaming: {name}"));
        }

        if let Err(error) = fs::rename(&plan.source_path, &plan.target_path).with_context(|| {
            let source_path = plan.source_path.display();
            let target_path = plan.target_path.display();
            format!("Failed to rename directory {source_path} -> {target_path}")
        }) {
            let source_path = plan.source_path.display();
            let target_path = plan.target_path.display();
            bar.println(format!(
                "Error renaming dir {source_path} -> {target_path}: {error}"
            ));
            error_count += 1;
        }

        bar.inc(1);
    }

    error_count
}

fn validate_dir_rename_plans(dir_plans: &[DirRenamePlan]) -> Result<()> {
    let mut seen_targets = BTreeMap::<String, &Path>::new();

    for plan in dir_plans {
        let source_key = normalize_conflict_key(&plan.source_path);
        let target_key = normalize_conflict_key(&plan.target_path);

        if plan.target_path.exists() && source_key != target_key {
            let source_path = plan.source_path.display();
            let target_path = plan.target_path.display();
            anyhow::bail!("Directory rename target already exists: {source_path} -> {target_path}");
        }

        if let Some(existing_source) = seen_targets.insert(target_key, plan.source_path.as_path()) {
            let existing_source = existing_source.display();
            let source_path = plan.source_path.display();
            let target_path = plan.target_path.display();
            anyhow::bail!(
                "Directory rename conflict: {existing_source} and {source_path} would both map to {target_path}"
            );
        }
    }

    Ok(())
}

fn normalize_conflict_key(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if cfg!(windows) || cfg!(target_os = "macos") {
        raw.to_lowercase()
    } else {
        raw.into_owned()
    }
}

fn relative_to_root(path: &Path, root_path: &Path) -> Result<PathBuf> {
    if path == root_path {
        return Ok(PathBuf::new());
    }

    path.strip_prefix(root_path)
        .map(Path::to_path_buf)
        .with_context(|| {
            let root_path = root_path.display();
            let path = path.display();
            format!("Failed to strip root path {root_path} from {path}")
        })
}

fn relative_parent_to_root(path: &Path, root_path: &Path) -> Result<PathBuf> {
    let parent = path.parent().unwrap_or(root_path);
    relative_to_root(parent, root_path)
}

fn append_relative_component(base: &Path, component: &OsString) -> PathBuf {
    if base.as_os_str().is_empty() {
        PathBuf::from(component)
    } else {
        base.join(component)
    }
}

fn path_depth(path: &Path) -> usize {
    path.components().count()
}

fn is_crab_dir(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.to_string_lossy().ends_with("[crab]"))
}

fn is_file_encrypted(path: &Path) -> bool {
    if path.extension() != Some(OsStr::new("crab")) {
        return false;
    }

    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };

    if metadata.len() < MIN_ENCRYPTED_FILE_LEN as u64 {
        return false;
    }

    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };

    let mut header = vec![0u8; MAGIC_HEADER.len()];
    if file.read_exact(&mut header).is_err() || header != MAGIC_HEADER {
        return false;
    }

    let mut salt = [0u8; 16];
    if file.read_exact(&mut salt).is_err() {
        return false;
    }

    let mut nonce = [0u8; 19];
    file.read_exact(&mut nonce).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const TEST_PASSWORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn test_validate_dir_rename_plans_rejects_existing_target() -> Result<()> {
        let temp_dir = tempdir()?;
        let source_path = temp_dir.path().join("source");
        let target_path = temp_dir.path().join("target");
        fs::create_dir_all(&source_path)?;
        fs::create_dir_all(&target_path)?;

        let plans = vec![DirRenamePlan {
            source_path,
            target_path,
            depth: 1,
        }];

        let error = match validate_dir_rename_plans(&plans) {
            Ok(()) => anyhow::bail!("expected an existing-target conflict"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("already exists"));
        Ok(())
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn test_validate_dir_rename_plans_rejects_case_insensitive_collisions() -> Result<()> {
        let plans = vec![
            DirRenamePlan {
                source_path: PathBuf::from("alpha"),
                target_path: PathBuf::from("Merged[crab]"),
                depth: 1,
            },
            DirRenamePlan {
                source_path: PathBuf::from("beta"),
                target_path: PathBuf::from("merged[crab]"),
                depth: 1,
            },
        ];

        let error = match validate_dir_rename_plans(&plans) {
            Ok(()) => anyhow::bail!("expected a case-insensitive rename collision"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("would both map"));
        Ok(())
    }

    #[test]
    fn test_build_encrypt_operation_plan_orders_children_before_parents() -> Result<()> {
        let temp_dir = tempdir()?;
        let root_path = temp_dir.path();
        let parent_dir = root_path.join("parent");
        let child_dir = parent_dir.join("child");
        fs::create_dir_all(&child_dir)?;
        fs::write(child_dir.join("data.txt"), b"payload")?;

        let snapshot = collect_snapshot(root_path);
        let name_master_key = derive_key(TEST_PASSWORD, NAME_MASTER_SALT)?;
        let operation_plan = build_encrypt_operation_plan(root_path, &snapshot, &name_master_key)?;

        assert_eq!(operation_plan.dir_plans.len(), 2);
        assert_eq!(
            operation_plan
                .dir_plans
                .first()
                .map(|plan| &plan.source_path),
            Some(&child_dir)
        );
        assert_eq!(
            operation_plan
                .dir_plans
                .get(1)
                .map(|plan| &plan.source_path),
            Some(&parent_dir)
        );
        Ok(())
    }

    #[test]
    fn test_is_file_encrypted_rejects_short_magic_only_file() -> Result<()> {
        let temp_dir = tempdir()?;
        let fake_encrypted_path = temp_dir.path().join("fake.crab");
        fs::write(&fake_encrypted_path, MAGIC_HEADER)?;

        assert!(!is_file_encrypted(&fake_encrypted_path));
        Ok(())
    }
}
