use argos_core::private_fs::{
    create_private_dir_all, open_private_file, write_private_file, PrivateOpenMode,
};

#[cfg(unix)]
#[test]
fn unix_private_objects_refuse_permissive_reuse() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("private");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let error =
        create_private_dir_all(&dir).expect_err("a permissive reused directory must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o777
    );

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = dir.join("secret");
    std::fs::write(&file, b"old secret bytes").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
    let error =
        write_private_file(&file, b"new").expect_err("a permissive reused file must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o666
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"old secret bytes");

    let error = open_private_file(&file, PrivateOpenMode::Append)
        .expect_err("append must not silently repair a permissive reused file");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}
