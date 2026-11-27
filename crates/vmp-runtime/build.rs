//! Embed QVMP_BLOB, optionally checking a trusted QVMP_BLOB_SHA256 before writing it.
//!
//! 使用：
//!   QVMP_BLOB=/path/to/hello.qvmp \
//!     cargo build --release --target aarch64-unknown-linux-gnu -p vmp-runtime

use sha2::{Digest, Sha256};
use std::env::{self, VarError};
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=QVMP_BLOB");
    println!("cargo:rerun-if-env-changed=QVMP_BLOB_SHA256");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let dest = out_dir.join("blob.bin");

    let expected = match env::var("QVMP_BLOB_SHA256") {
        Ok(value) => {
            assert!(
                value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
                "QVMP_BLOB_SHA256 must contain 64 hexadecimal digits"
            );
            Some(value)
        }
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(_)) => panic!("QVMP_BLOB_SHA256 must be hexadecimal"),
    };
    let path = env::var_os("QVMP_BLOB").map(PathBuf::from);
    let bytes = match path {
        Some(path) => {
            println!("cargo:rerun-if-changed={}", path.display());
            if path.is_file() {
                fs::read(&path).unwrap_or_else(|error| {
                    panic!("cannot read QVMP_BLOB {}: {error}", path.display())
                })
            } else {
                assert!(expected.is_none(), "QVMP_BLOB is not a file: {}", path.display());
                println!("cargo:warning=QVMP_BLOB 路径无效，使用空 blob: {}", path.display());
                Vec::new()
            }
        }
        None if expected.is_some() => panic!("QVMP_BLOB_SHA256 requires QVMP_BLOB"),
        None => Vec::new(),
    };
    if let Some(expected) = expected {
        let actual = format!("{:x}", Sha256::digest(&bytes));
        assert!(actual.eq_ignore_ascii_case(&expected), "QVMP_BLOB SHA-256 mismatch");
    }
    fs::write(dest, &bytes).expect("write embedded blob");
}
