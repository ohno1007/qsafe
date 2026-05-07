//! vmp-runtime —— 受保护程序的「外壳」二进制。
//!
//! 用法（Linux/aarch64 交叉编译）：
//! ```
//!   # 1) 用 vmp CLI 生成 blob
//!   ./target/release/vmp protect ./hello.elf -o hello.qvmp --level heavy
//!
//!   # 2) 把 blob 嵌入 runtime 并交叉编译
//!   QVMP_BLOB=$(pwd)/hello.qvmp \
//!     cargo build --release --target aarch64-unknown-linux-gnu -p vmp-runtime
//!
//!   # 3) 在 aarch64-linux 上运行（这就是「写回后的宿主二进制」）
//!   ./target/aarch64-unknown-linux-gnu/release/vmp-runtime
//! ```
//!
//! 默认入口约定：dispatch_vm(blob, region=0, args=[argc, argv ptr, envp, ...])。
//! 你可以通过 `--region <N>` 命令行参数选择其它 region 作为 entry。

use std::env;
use std::process;

const EMBEDDED_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blob.bin"));

fn main() {
    #[cfg(feature = "dev-logger")]
    {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    }
    log::debug!("stage 1: enter main");
    let args: Vec<String> = env::args().collect();
    log::debug!("stage 2: argv ok ({} args)", args.len());
    let mut entry_region_override: Option<usize> = None;
    let mut blob_path: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--region" => {
                i += 1;
                entry_region_override = Some(args[i].parse().expect("--region 需要数字"));
            }
            "--blob" => {
                i += 1;
                blob_path = Some(args[i].clone());
            }
            "-h" | "--help" => {
                print_help();
                return;
            }
            _ => {}
        }
        i += 1;
    }

    // 优先使用 --blob 指定的外部文件；否则用编译时嵌入的 EMBEDDED_BLOB。
    let owned;
    let blob_bytes: &[u8] = if let Some(p) = blob_path.as_deref() {
        owned = std::fs::read(p).unwrap_or_else(|e| {
            let _ = (p, e);
            eprintln!("E:io");
            process::exit(127);
        });
        &owned
    } else {
        EMBEDDED_BLOB
    };

    log::debug!("stage 3: blob_bytes len={}", blob_bytes.len());
    if blob_bytes.is_empty() {
        eprintln!("E:no-blob");
        process::exit(127);
    }

    let blob = vmp_stub::unpack_blob(blob_bytes).unwrap_or_else(|_| {
        eprintln!("E:blob");
        process::exit(126);
    });
    log::debug!(
        "stage 4: blob unpacked, regions={} pool={} entry_region={}",
        blob.regions.len(),
        blob.bytecode_pool.len(),
        blob.entry_region
    );

    let entry_region = entry_region_override.unwrap_or(blob.entry_region as usize);
    if entry_region >= blob.regions.len() {
        eprintln!("E:region");
        process::exit(125);
    }

    log::debug!("stage 5: building host");
    let mut host = vmp_stub::linux::LinuxHost::new();

    // 把 argc/argv 指针作为前两个参数传入（与 _start ABI 接近）。
    let argv_ptrs: Vec<u64> = args
        .iter()
        .map(|s| s.as_ptr() as u64)
        .collect();
    let argv_ptr = argv_ptrs.as_ptr() as u64;

    let vm_args: [u64; 8] = [
        args.len() as u64,
        argv_ptr,
        0, 0, 0, 0, 0, 0,
    ];

    log::debug!("stage 6: entering dispatch_vm region={}", entry_region);
    match vmp_stub::dispatch_vm(&blob, entry_region, &vm_args, &mut host) {
        Ok(retval) => {
            log::debug!("stage 7: VM returned {}", retval);
            // 与 main() 返回值一致：低 8 位作为退出码
            process::exit(retval as i32);
        }
        Err(_) => {
            eprintln!("E:vm");
            process::exit(124);
        }
    }
}

fn print_help() {
    // help 文本只在 debug build 暴露 (release 直接打印简短提示，避免泄漏命令行结构)
    #[cfg(debug_assertions)]
    {
        println!(
            "vmp-runtime — 受保护程序的虚拟化执行外壳

用法:
  vmp-runtime [--region N] [--blob path]

参数:
  --region N    选择 entry region 索引 (默认从 blob.entry_region)
  --blob path   从外部文件加载 blob (覆盖编译时嵌入)

构建提示:
  设置 QVMP_BLOB=/path/to/file.qvmp 再 cargo build，blob 会被静态嵌入。"
        );
    }
    #[cfg(not(debug_assertions))]
    println!("usage: -h");
}
