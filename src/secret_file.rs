//! Secret-bearing files must be private from creation, including sibling temps.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

/// Refuse existing files/symlinks instead of following a predictable temp name.
/// On Unix, request 0600 at creation; chmod after writing leaves an exposure gap.
pub(crate) fn create_new(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let result = file.write_all(data).and_then(|()| file.sync_all());
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_creation_refuses_existing_files_and_symlinks() {
        let dir = std::env::temp_dir().join(format!("ag-secret-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("secret");
        create_new(&target, b"dummy-secret").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let link = dir.join("link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert_eq!(
                create_new(&link, b"overwrite").unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );
        }
        assert_eq!(
            create_new(&target, b"overwrite").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"dummy-secret");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
