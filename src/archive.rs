use anyhow::{Context, Result, anyhow};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use tar::{Archive, EntryType};

pub(crate) fn unpack_archive(reader: impl Read, dist_dir: &Path) -> Result<()> {
    let mut archive = Archive::new(reader);

    for entry in archive.entries()? {
        let mut entry = entry?;
        unpack_archive_entry(&mut entry, dist_dir)?;
    }

    Ok(())
}

fn validate_archive_entry_path(entry_path: &Path) -> Result<()> {
    if entry_path.is_absolute() {
        return Err(anyhow!(
            "Illegal archive entry path: {}",
            entry_path.display()
        ));
    }

    if entry_path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(anyhow!(
            "Illegal archive entry path: {}",
            entry_path.display()
        ));
    }

    Ok(())
}

fn validate_archive_entry_type(entry_type: EntryType, entry_path: &Path) -> Result<()> {
    if entry_type.is_file() || entry_type.is_dir() {
        return Ok(());
    }

    let entry_path = entry_path.display();
    Err(anyhow!(
        "Unsupported archive entry type {entry_type:?} for {entry_path}"
    ))
}

fn ensure_directory_exists_in_dist(dist_dir: &Path, dir: &Path) -> Result<()> {
    let mut ancestor = dir;
    let mut dirs_to_create = Vec::<PathBuf>::new();

    while fs::symlink_metadata(ancestor).is_err() {
        dirs_to_create.push(ancestor.to_path_buf());
        ancestor = ancestor.parent().ok_or_else(|| {
            let dir = dir.display();
            anyhow!("Failed to resolve parent path while preparing archive destination {dir}")
        })?;
    }

    for ancestor in dirs_to_create.iter().rev() {
        if let Some(parent) = ancestor.parent() {
            validate_inside_dist(dist_dir, parent)?;
        }

        fs::create_dir(ancestor)
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists
                    && fs::metadata(ancestor).is_ok_and(|metadata| metadata.is_dir())
                {
                    return Ok(());
                }
                Err(error)
            })
            .with_context(|| {
                let ancestor = ancestor.display();
                format!("Failed to create archive destination directory {ancestor}")
            })?;
    }

    Ok(())
}

fn validate_inside_dist(dist_dir: &Path, path: &Path) -> Result<()> {
    let canonical_path = path.canonicalize().with_context(|| {
        let path = path.display();
        format!("Failed to canonicalize archive destination path {path}")
    })?;
    let canonical_dist_dir = dist_dir.canonicalize().with_context(|| {
        let dist_dir = dist_dir.display();
        format!("Failed to canonicalize extraction root {dist_dir}")
    })?;

    if !canonical_path.starts_with(&canonical_dist_dir) {
        let path = path.display();
        anyhow::bail!("Refusing to unpack archive entry outside destination root via {path}");
    }

    Ok(())
}

fn unpack_archive_entry<R: Read>(entry: &mut tar::Entry<R>, dist_dir: &Path) -> Result<()> {
    let entry_path = entry.path()?.into_owned();
    validate_archive_entry_path(&entry_path)?;

    let entry_type = entry.header().entry_type();
    validate_archive_entry_type(entry_type, &entry_path)?;

    let target_path = dist_dir.join(&entry_path);
    if target_path.exists() {
        let target_path = target_path.display();
        return Err(anyhow!(
            "Refusing to overwrite existing path during extraction: {target_path}"
        ));
    }

    if entry_type.is_dir() {
        ensure_directory_exists_in_dist(dist_dir, &target_path).with_context(|| {
            let target_path = target_path.display();
            format!("Failed to create directory for archive entry {target_path}")
        })?;
        return Ok(());
    }

    if let Some(parent) = target_path.parent() {
        ensure_directory_exists_in_dist(dist_dir, parent).with_context(|| {
            let target_path = target_path.display();
            format!("Failed to create parent directory for {target_path}")
        })?;
        validate_inside_dist(dist_dir, parent)?;
    }

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target_path)
        .with_context(|| {
            let target_path = target_path.display();
            format!("Failed to create output file {target_path}")
        })?;

    std::io::copy(entry, &mut output).with_context(|| {
        let target_path = target_path.display();
        format!("Failed to unpack archive entry into {target_path}")
    })?;
    output.flush().with_context(|| {
        let target_path = target_path.display();
        format!("Failed to flush unpacked archive entry {target_path}")
    })?;

    Ok(())
}
