use argos_core::private_fs::{
    create_private_dir_all, open_private_file, write_private_file, PrivateOpenMode,
};

#[cfg(unix)]
#[test]
fn unix_private_objects_tighten_reused_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("private");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    create_private_dir_all(&dir).unwrap();
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );

    let file = dir.join("secret");
    std::fs::write(&file, b"old secret bytes").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
    write_private_file(&file, b"new").unwrap();
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"new");

    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
    let opened = open_private_file(&file, PrivateOpenMode::Append).unwrap();
    assert_eq!(
        opened.metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
}
