//! 构建脚本：把 `QVMP_BLOB`（或默认 `qvmp_blob.bin`）拷贝到 OUT_DIR/blob.bin，
//! 供 `include_bytes!(concat!(env!("OUT_DIR"), "/blob.bin"))` 在运行时嵌入。
//!
//! 使用：
//!   QVMP_BLOB=/path/to/hello.qvmp \
//!     cargo build --release --target aarch64-unknown-linux-gnu -p vmp-runtime

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let dest = out_dir.join("blob.bin");

    let src = env::var("QVMP_BLOB").ok();
    if let Some(s) = src {
        let p = PathBuf::from(&s);
        if let Ok(meta) = fs::metadata(&p) {
            if meta.is_file() {
                fs::copy(&p, &dest).expect("拷贝 QVMP_BLOB 失败");
                println!("cargo:rerun-if-changed={}", p.display());
                println!("cargo:warning=vmp-runtime 嵌入 blob: {} ({} 字节)", p.display(), meta.len());
                println!("cargo:rerun-if-env-changed=QVMP_BLOB");
                return;
            }
        }
        println!("cargo:warning=QVMP_BLOB 路径无效，使用空 blob: {}", s);
    }

    // 默认：写入空 blob，使运行时输出错误信息。
    fs::write(&dest, [0u8; 0]).expect("写入空 blob");
    println!("cargo:rerun-if-env-changed=QVMP_BLOB");
}
