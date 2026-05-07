//! .a 静态库重写。
//!
//! 流程：
//!   1. 解 archive → 列 .o 成员（已由 [`vmp_loader::ar::members`] 实现）
//!   2. 对每个 .o：lift → protect blob → rewrite .o
//!      - 注意 .o 是 ET_REL（可重定位），`vmp_loader::elf::parse` 当前把它归类为
//!        `BinaryKind::Other`，rewriter 主路径 [`crate::elf_writer::rewrite_elf`]
//!        默认拒绝。**.a 重写在 archive 层而非 .o 层做**：保留每个 .o 完整字节，
//!        仅在 archive 末尾追加一个 `.qvmp_static.<idx>` 成员承载 stub blob，
//!        并在 archive 头记录每个原 .o 文件中的 trampoline patch 地址。
//!   3. 重新 pack archive：保持 ar header / GNU 长名表 / 偶数对齐
//!
//! 这样链接器仍然按原方式取每个 .o；blob 作为额外 archive 成员被链接器原样合入
//! 输出 .so / .exe（之后由 cdylib runtime 在 ELF 加载时扫到）。该方案不依赖
//! 静态链接器修改，对所有支持 ar 的链接器（ld / lld / link.exe lib 模式）都生效。
//!
//! 当前实现：MVP — 不做 .o 内 lift（lift 阶段需要 .o 内 R_AARCH64_CALL26 重定位
//! 才能跨 .o 跳转，工作量大）。本 pass 只把整段 stub blob 追加为新 archive 成员，
//! 让上层 link 路径能拿到。完整 lift 留给 Phase 5 与 cdylib runtime 联动。

use crate::Result;
use vmp_loader::ar;
use vmp_stub::{pack_blob, StubBlob};

#[derive(Debug, Clone, Default)]
pub struct ArRewriteOptions {
    /// blob 成员名（默认 `qvmp_blob.o`）。链接器对 `.o` 后缀的成员会尝试解析；
    /// 加 `.bin` 后缀可让 lld 把它当 unknown object 直接放进输出二进制 .data 段。
    pub member_name: Option<String>,
}

#[derive(Debug, Default)]
pub struct ArRewriteReport {
    pub original_members: usize,
    pub blob_member_offset: u64,
    pub blob_member_size: u64,
    pub output_size: u64,
}

/// 把 `blob` 作为额外成员追加到 archive 末尾，输出新 archive 字节。
pub fn rewrite_archive(
    archive_bytes: &[u8],
    blob: &StubBlob,
    opts: &ArRewriteOptions,
) -> Result<(Vec<u8>, ArRewriteReport)> {
    let mems = ar::members(archive_bytes)
        .map_err(|e| crate::RewriteError::Parse(format!("ar parse: {e}")))?;

    let blob_payload = {
        let mut p = Vec::with_capacity(8 + 1024);
        p.extend_from_slice(b"QVMP");
        let packed = pack_blob(blob);
        p.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        p.extend_from_slice(&packed);
        p
    };

    let member_name = opts.member_name.clone().unwrap_or_else(|| "qvmp_blob.bin".into());

    // archive 总是以原字节流为基础（含 ar header + 长名表 + 各成员 padding），
    // 在末尾对齐 2 字节后追加新 header + payload。
    let mut out = archive_bytes.to_vec();
    if out.len() % 2 != 0 {
        out.push(b'\n');
    }

    let header_off = out.len();
    out.extend_from_slice(&build_ar_header(&member_name, blob_payload.len()));
    out.extend_from_slice(&blob_payload);
    if out.len() % 2 != 0 {
        out.push(b'\n');
    }
    let report = ArRewriteReport {
        original_members: mems.len(),
        blob_member_offset: header_off as u64,
        blob_member_size: blob_payload.len() as u64,
        output_size: out.len() as u64,
    };
    Ok((out, report))
}

/// 构造一个 ar 60 字节 header（System V / GNU 风格）。
fn build_ar_header(name: &str, size: usize) -> [u8; 60] {
    let mut h = [b' '; 60];
    // 名字字段 0..16 —— 短名末尾加 '/'，长名（>15 char）这里简化：截断到 15 + '/'
    let nbytes = name.as_bytes();
    let n_used = nbytes.len().min(15);
    h[..n_used].copy_from_slice(&nbytes[..n_used]);
    h[n_used] = b'/';
    // mtime 16..28 = "0"
    let mtime = b"0";
    h[16..16 + mtime.len()].copy_from_slice(mtime);
    // owner 28..34 = "0"
    h[28] = b'0';
    // group 34..40 = "0"
    h[34] = b'0';
    // mode 40..48 = "100644"
    h[40..46].copy_from_slice(b"100644");
    // size 48..58 ASCII decimal
    let size_str = format!("{}", size);
    let sb = size_str.as_bytes();
    h[48..48 + sb.len()].copy_from_slice(sb);
    // 终结符 58..60 = "`\n"
    h[58] = b'`';
    h[59] = b'\n';
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmp_isa::IsaRandomizer;

    fn empty_archive() -> Vec<u8> {
        b"!<arch>\n".to_vec()
    }

    fn dummy_blob() -> StubBlob {
        let spec = IsaRandomizer::new(1, 1, false).build();
        StubBlob {
            spec,
            regions: vec![],
            bytecode_pool: vec![],
            entry_region: 0,
            data_segments: vec![],
        }
    }

    #[test]
    fn rewrite_appends_member() {
        let original = empty_archive();
        let blob = dummy_blob();
        let (out, report) = rewrite_archive(&original, &blob, &ArRewriteOptions::default()).unwrap();
        assert!(out.len() > original.len());
        assert_eq!(report.original_members, 0);
        assert!(report.blob_member_size > 0);
        // 新 member header 的 magic
        let header_off = report.blob_member_offset as usize;
        assert_eq!(&out[header_off + 58..header_off + 60], b"`\n");
    }
}
