//! APK 加壳 wrapper 工具 —— 编排层。
//!
//! Qsafe VMP 不直接处理 APK zip 容器（避免引入 zip / apksigner 依赖；这两步用
//! 系统命令 `unzip` / `apksigner` / `zipalign` 即可）。本模块假设调用方已经
//! **解包 APK 到目录**，提供：
//!
//! - 扫描 APK 目录，列出 `lib/<abi>/*.so`
//! - 对每个 .so 调 `vmp protect` + `vmp rewrite` 流水线（只面向 arm64-v8a；其他 ABI
//!   按 docs/APK_PACKING.md 的策略保留原 .so）
//! - 输出 (原 .so 路径, 新 .so 路径, 报告) 列表，由调用方决定写回 / 重签
//!
//! 完整 APK pipeline 看 docs/APK_PACKING.md。

use crate::elf_writer::{rewrite_elf, RewriteOptions};
use crate::Result;
use std::path::{Path, PathBuf};
use vmp_loader::LoadedObject;
use vmp_stub::StubBlob;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiTarget {
    /// arm64-v8a — 当前 lifter 完全支持
    Arm64,
    /// armeabi-v7a — lifter 是 MVP 子集（见 vmp-arch::arm32）
    Arm32,
    /// x86_64 — lifter 是 MVP 子集
    X86_64,
}

impl AbiTarget {
    pub fn dir_name(&self) -> &'static str {
        match self {
            AbiTarget::Arm64 => "arm64-v8a",
            AbiTarget::Arm32 => "armeabi-v7a",
            AbiTarget::X86_64 => "x86_64",
        }
    }
}

/// 一条 .so 的处理报告。
#[derive(Debug)]
pub struct ApkLibReport {
    pub original_path: PathBuf,
    pub abi: AbiTarget,
    pub size_before: u64,
    pub size_after: u64,
    pub regions: usize,
}

/// 扫描 APK 解包目录里的所有 native lib。
///
/// `apk_dir` 通常是 `unzip -d apk_unpacked your.apk` 后的根目录，
/// 期望含 `lib/<abi>/*.so`。
pub fn list_libs(apk_dir: &Path) -> std::io::Result<Vec<(AbiTarget, PathBuf)>> {
    let mut out = Vec::new();
    let abi_list = [AbiTarget::Arm64, AbiTarget::Arm32, AbiTarget::X86_64];
    for abi in abi_list.iter() {
        let dir = apk_dir.join("lib").join(abi.dir_name());
        if !dir.exists() {
            continue;
        }
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.extension().map(|e| e == "so").unwrap_or(false) {
                out.push((*abi, p));
            }
        }
    }
    Ok(out)
}

/// 对一个 .so 应用「protect → rewrite」。caller 负责构造 `blob`（通常 `vmp protect`
/// 链路输出）以及决定 RewriteOptions。
///
/// 注意：本函数是 **rewriter 阶段封装** —— protect (lift+codegen) 阶段在 vmp-cli
/// `Cmd::Protect` 已经独立完成。这里只做嵌入与跳板写入，符合 APK 路径需要批量
/// 处理多个 .so 的常见用法。
pub fn pack_one_lib(
    loaded: &LoadedObject,
    blob: &StubBlob,
    opts: &RewriteOptions,
    abi: AbiTarget,
) -> Result<(Vec<u8>, ApkLibReport)> {
    let size_before = loaded.raw.len() as u64;
    let (out, _rep) = rewrite_elf(loaded, blob, opts)?;
    Ok((
        out.clone(),
        ApkLibReport {
            original_path: PathBuf::new(),
            abi,
            size_before,
            size_after: out.len() as u64,
            regions: blob.regions.len(),
        },
    ))
}

/// 把 cdylib `libqvmp_runtime.so` 的路径写到 APK 解包目录的 `lib/<abi>/`
/// （通常调用方在交叉编译完 cdylib 后用此函数把产物路由进 APK）。
/// 这里仅做路径计算，不做文件操作 —— 由 caller 决定 std::fs::copy。
pub fn runtime_target_path(apk_dir: &Path, abi: AbiTarget) -> PathBuf {
    apk_dir
        .join("lib")
        .join(abi.dir_name())
        .join("libqvmp_runtime.so")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_libs_empty_when_missing() {
        let tmp = std::env::temp_dir().join("qvmp_apk_test_empty");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let r = list_libs(&tmp).unwrap();
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn runtime_path_correct() {
        let p = runtime_target_path(Path::new("/tmp/apk"), AbiTarget::Arm64);
        assert!(p.ends_with("lib/arm64-v8a/libqvmp_runtime.so"));
    }
}
