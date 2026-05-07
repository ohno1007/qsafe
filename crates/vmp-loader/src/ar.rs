//! AR(.a) 静态库解析。
//!
//! ar 是一个简单的归档格式：开头 `!<arch>\n`，然后是若干 60-byte header + 数据的成员。
//! 每个成员通常是一个 ELF .o 文件。我们把整个 archive 加载后，对**每个 .o 中的可执行
//! section** 都暴露为一段 `CodeRegion`，函数符号合并到 `LoadedObject.symbols`。
//!
//! Rewriter 端要做的事是逐 .o 重写并把结果写回归档（保留同样的 ar 格式）。本模块只
//! 提供「读」的能力 + 一个 `members()` 函数让 rewriter 知道每个成员的字节范围。

use crate::{BinaryKind, LoadedObject};
use goblin::elf::Elf;
use vmp_core::{Arch, CodeRegion, Error, ObjectFormat, Os, Result, Symbol};

#[derive(Debug, Clone)]
pub struct ArMember {
    pub name: String,
    /// 在原 ar 字节流中的偏移
    pub offset: usize,
    pub size: usize,
}

pub fn members(bytes: &[u8]) -> Result<Vec<ArMember>> {
    if bytes.len() < 8 || &bytes[..8] != b"!<arch>\n" {
        return Err(Error::parse("不是合法的 AR 静态库（缺 magic）"));
    }
    let mut members = Vec::new();
    let mut pos = 8usize;
    // GNU 长名表: 第一个名字以 "//" 开头的成员
    let mut long_names: Vec<u8> = Vec::new();

    while pos + 60 <= bytes.len() {
        let header = &bytes[pos..pos + 60];
        // 名字 0..16，'/'-terminated 或 GNU 长名表 / 偏移引用
        let name_field = std::str::from_utf8(&header[0..16]).unwrap_or("");
        // size 字段在 48..58, ASCII decimal
        let size_str = std::str::from_utf8(&header[48..58]).unwrap_or("0");
        let size: usize = size_str.trim().parse().map_err(|_| Error::parse("AR size 字段无效"))?;
        let data_off = pos + 60;

        let name = parse_member_name(name_field, &long_names);

        if name == "//" {
            // GNU 长名字符串表
            long_names = bytes[data_off..data_off + size].to_vec();
        } else if name == "/" || name.is_empty() {
            // 符号索引表（System V 风格）；跳过
        } else {
            members.push(ArMember {
                name,
                offset: data_off,
                size,
            });
        }

        // member 结尾按 2 字节对齐
        let next = data_off + size;
        pos = if next % 2 != 0 { next + 1 } else { next };
    }
    Ok(members)
}

fn parse_member_name(name_field: &str, long_names: &[u8]) -> String {
    let trimmed = name_field.trim_end();
    if let Some(rest) = trimmed.strip_prefix('/') {
        // GNU 长名表偏移：/<offset>
        if let Ok(off) = rest.parse::<usize>() {
            if off < long_names.len() {
                let end = long_names[off..]
                    .iter()
                    .position(|&b| b == b'/' || b == b'\n')
                    .unwrap_or(long_names.len() - off);
                return String::from_utf8_lossy(&long_names[off..off + end]).to_string();
            }
        }
        // BSD-style 名字 / 或符号表 / —— 保持原样
        return trimmed.to_string();
    }
    // 短名以 '/' 结尾：name.o/
    trimmed.trim_end_matches('/').to_string()
}

pub fn parse(bytes: Vec<u8>) -> Result<LoadedObject> {
    let mems = members(&bytes)?;
    let mut all_code = Vec::new();
    let mut all_syms = Vec::new();
    let mut arch = Arch::Arm64;
    let mut os = Os::Linux;

    // 给每个 .o 一段虚拟基址：从 0x4000_0000 开始，每个 .o 间隔 4MB（避免地址冲突）
    let mut next_base: u64 = 0x4000_0000;
    for m in &mems {
        if m.size == 0 || !m.name.ends_with(".o") {
            continue;
        }
        let blob = &bytes[m.offset..m.offset + m.size];
        let elf = match Elf::parse(blob) {
            Ok(e) => e,
            Err(_) => continue,
        };
        match elf.header.e_machine {
            goblin::elf::header::EM_AARCH64 => arch = Arch::Arm64,
            goblin::elf::header::EM_X86_64 => arch = Arch::X86_64,
            _ => {}
        }
        // .o 文件 sh_addr 一般是 0；用 next_base 偏移
        for sh in &elf.section_headers {
            const SHF_EXECINSTR_LOCAL: u32 = 0x4;
            if (sh.sh_flags as u32) & SHF_EXECINSTR_LOCAL != 0 && sh.sh_size > 0 {
                let start = sh.sh_offset as usize;
                let end = start + sh.sh_size as usize;
                if end > blob.len() {
                    continue;
                }
                all_code.push(CodeRegion {
                    vaddr: next_base,
                    bytes: blob[start..end].to_vec(),
                });
                next_base += 4 * 1024 * 1024;
            }
        }
        // 符号：把每个函数符号 vaddr 偏移到 next_base 之前的 region 起点
        // 简化：跳过具体重定位，只记录函数名 + 大小（vaddr=0 表示需要进一步绑定）
        for sym in elf.syms.iter() {
            if sym.is_function() && sym.st_size > 0 {
                if let Some(Ok(name)) = elf.strtab.get(sym.st_name) {
                    all_syms.push(Symbol {
                        name: format!("{}::{}", m.name, name),
                        vaddr: sym.st_value,
                        size: sym.st_size,
                    });
                }
            }
        }
    }
    let _ = os;

    Ok(LoadedObject {
        arch,
        os: Os::Linux,
        format: ObjectFormat::Elf,
        kind: BinaryKind::StaticArchive,
        code: all_code,
        symbols: all_syms,
        entry: 0,
        raw: bytes,
    })
}
