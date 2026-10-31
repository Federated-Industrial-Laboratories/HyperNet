// SPDX-License-Identifier: MIT
// Unit tests for RuntimeFiles.
use super::*;
#[test]
fn failed_child_reports_bounded_escaped_stderr_without_stdout() {
    let error = capture(
        Path::new("/usr/bin/sh"),
        &strings(&[
            "-c",
            "printf 'private output'; printf '\\033[31mhelper failed\\n' >&2; exit 7",
        ]),
        5,
        1024,
        1024,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("helper failed"));
    assert!(error.contains("exit status: 7"));
    assert!(error.contains("\\x1b[31m"));
    assert!(!error.contains("private output"));
    assert!(!error.chars().any(char::is_control));
    let long = diagnostic(&[0x1b; 1025]);
    assert_eq!(long.len(), 4096 + " [truncated]".len());
    assert!(long.ends_with(" [truncated]"));
}
#[test]
fn bounded_exchange_drains_input_and_output_without_pipe_deadlock() {
    let packet = (0..MAXIMUM).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let (output, errors) = capture_input(
        Path::new("/usr/bin/cat"),
        &[],
        5,
        MAXIMUM,
        1024,
        Some(&packet),
    )
    .unwrap();
    assert_eq!(output, packet);
    assert!(errors.is_empty());
    assert!(capture_input(Path::new("/usr/bin/cat"), &[], 5, 1024, 1024, Some(&packet)).is_err());
    assert!(
        capture_input(
            Path::new("/usr/bin/cat"),
            &[],
            5,
            MAXIMUM,
            1024,
            Some(&vec![0; MAXIMUM + 1])
        )
        .is_err()
    );
}
#[test]
fn private_reads_refuse_links_and_special_files() {
    let root = std::env::temp_dir().join(format!("HyperNetRuntimeFiles{}", random_id()));
    directory(&root).unwrap();
    create(&root.join("Original"), b"private").unwrap();
    fs::hard_link(root.join("Original"), root.join("Linked")).unwrap();
    assert!(read(&root.join("Linked"), 64).is_err());
    std::os::unix::fs::symlink("Original", root.join("Symbolic")).unwrap();
    assert!(read(&root.join("Symbolic"), 64).is_err());
    use std::os::unix::ffi::OsStrExt;
    let fifo = std::ffi::CString::new(root.join("Fifo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(read(&root.join("Fifo"), 64).is_err());
    fs::remove_dir_all(root).unwrap();
}
