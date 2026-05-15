//! ELF 重写：在原 ELF 末尾追加 PT_LOAD segment，把 stub blob + 跳板表写入新段，
//! 同时在每个被保护函数的入口写一条 `B <trampoline>`。
//!
//! 实现策略最小可行版（**MVP**）：
//! 1. 把整个原 ELF 字节流读到内存。
//! 2. 在文件末尾追加：
//!    - 跳板表：每个 region 一个 16-byte 跳板（顺序与 `regions` 一致）
//!    - magic + blob 长度 + blob 字节
//! 3. 给原 ELF 增加一个新的 program-header 项（PT_LOAD，可读+可执行）。
//!    - 这要求 ELF 文件原本在 `e_phoff..e_phoff + e_phnum * e_phentsize` 之后还有
//!      足够空间放新 entry；否则得整体 relocate program-header 表（更复杂）。
//!    - 实践上 LLD 链接的 ELF 通常 e_phoff 紧跟 ELF header 后，phdr 之后是 .interp
//!      或第一个 LOAD segment，没有空隙。**这里把 phdr 整体复制到文件末尾的新位置**
//!      并把 `e_phoff` 指向新位置（这样能放下额外条目）。
//! 4. 在每个 region 的 patch_addr 写 `B <对应跳板虚拟地址>`。
//!
//! 注意：
//! - 不重写 .dynsym / .dynamic / .rela.dyn —— 不动这些不会破坏现有动态链接。
//! - 不修复 .eh_frame —— 我们覆盖的指令位于函数入口，正常异常展开不会回退到首条指令。
//! - 新追加的 segment 不写入任何 dynamic 标记，OS 加载时把它当普通可执行 LOAD 段。

use crate::patcher::{build_brk_trampoline, encode_b};
use crate::{Result, RewriteError};
use byteorder::{ByteOrder, LittleEndian};
use vmp_loader::{BinaryKind, LoadedObject};
use vmp_stub::{pack_blob, StubBlob, StubRegion};

#[derive(Debug, Default, Clone)]
pub struct RewriteOptions {
    /// 输出新 ELF 时是否也把每个 region 的 `patch_addr` 写一条 B 跳板。
    /// 关闭时仅嵌入 blob，不动原 .text（适合"先嵌入字节码后续再 patch"的两阶段）。
    pub write_entry_trampolines: bool,
    /// 嵌入 cdylib runtime（libqvmp_runtime.so 的字节）。提供后 rewriter 会：
    ///   1. 把 .so bytes 追加到新 LOAD segment 末尾
    ///   2. 生成 bootstrap stub (open+write+dlopen+unlink)
    ///   3. 在 INIT_ARRAY 头插一条指向 bootstrap 的入口
    /// 这样最终 ELF 是完全自包含的，运行时不需要单独的 .so 文件。
    pub embed_runtime_so: Option<Vec<u8>>,
    /// 诊断模式：让 e_entry shim 在 bootstrap 返回后用 bootstrap 的 x0 作为
    /// SYS_exit_group 的退出码，而不是 tail-call 原 `_start`。这样 MT 管理器
    /// 的进程结束对话框直接显示 stage code，无需用户去 cat trace 文件。
    pub shim_exit_diagnostic: bool,
    /// 添加 DT_NEEDED dependency 到 .dynamic。Android linker 在跑 main exec 的
    /// INIT_ARRAY 之前就先加载这个 .so（安全的 dlopen 时机），避开"在 INIT_ARRAY
    /// 或 signal handler 里 dlopen 触发栈金丝雀"的问题。需要用户把对应 .so
    /// 放在这个路径下。实现方式：把 DT_DEBUG 条目替换成 DT_NEEDED，把字符串
    /// 加到新 .dynstr 末尾，更新 DT_STRTAB/DT_STRSZ。
    pub dt_needed_path: Option<String>,
}

#[derive(Debug, Default)]
pub struct RewriteReport {
    pub patched_entries: usize,
    pub trampoline_table_offset: u64,
    pub blob_offset: u64,
    pub new_segment_vaddr: u64,
    pub new_segment_size: u64,
    /// 当 `RewriteOptions::embed_runtime_so` 提供时填充：
    pub embedded_so_vaddr: u64,
    pub embedded_so_len: u64,
    pub bootstrap_vaddr: u64,
    pub init_array_vaddr: u64,
}

/// 把 `blob` 嵌入 `loaded` 原 ELF，写入跳板（可选），返回新 ELF 字节。
pub fn rewrite_elf(
    loaded: &LoadedObject,
    blob: &StubBlob,
    opts: &RewriteOptions,
) -> Result<(Vec<u8>, RewriteReport)> {
    if !matches!(loaded.kind, BinaryKind::Executable | BinaryKind::SharedObject) {
        return Err(RewriteError::Unsupported);
    }
    let mut out = loaded.raw.clone();

    // 关键：选 vaddr 同时拿到原有 LOAD 的最大 p_align（典型现代 ARM64 binary
    // 是 0x4000 = 16KB）。新 LOAD 必须用同样对齐，否则 16KB 页设备 mmap 会
    // 跟前段最后一页冲突 → bionic 报通用 PIE error。
    let (next_load_vaddr_val, page_align_u64) = next_load_vaddr(&loaded.raw)?;
    let page_align = page_align_u64 as usize;

    // ---- 1. 用 identity mapping (p_offset == p_vaddr) 放新 LOAD ----
    // Android 14+ 某些 kernel/linker 路径用 `load_bias + e_phoff` 算 AT_PHDR
    // (回退分支)，把 PHDR.p_offset 当 vaddr 用。所以新 LOAD 必须满足
    // file_off == vaddr.
    //
    // 但: 原 ELF 末尾常有 .debug_* / .strtab / section header table 等
    // unloaded 内容把文件撑大. 如果 next_load_vaddr (= max(load_vaddr+memsz),
    // 页对齐) 小于 out.len(), 直接 append 就会让 trampoline 落在
    // file_off > new_vaddr_base 的位置 — LOAD segment 把 0x70000..0xC4000
    // 映射成 RX, 但其中前半截是 stale debug bytes; 任何被 patch 的
    // `B trampoline=0x70000+N*16` 都跳到 debug 数据当指令解 → SIGILL.
    //
    // 修正: new_vaddr_base 取 max(next_load_vaddr, ceil(file_size, page))
    // — 两个约束都满足: file_off==vaddr + 不撞已有文件内容.
    let aligned_file_end = {
        let mask = page_align_u64 - 1;
        ((out.len() as u64) + mask) & !mask
    };
    let new_vaddr_base = next_load_vaddr_val.max(aligned_file_end);
    let new_segment_off = new_vaddr_base as usize;
    while out.len() < new_segment_off {
        out.push(0);
    }

    // ---- 2. 跳板表（每个 region 16 字节）----
    let trampoline_table_off = out.len();
    for (idx, _r) in blob.regions.iter().enumerate() {
        let tramp = build_brk_trampoline(idx as u32);
        out.extend_from_slice(&tramp);
    }

    // ---- 3. 嵌入 blob ----
    // Header layout (32 bytes total):
    //   [0..4]   "QVMP"
    //   [4..8]   payload_len:u32
    //   [8..16]  rodata_vaddr:u64   (filled by armor::encrypt_rodata)
    //   [16..24] rodata_len:u64
    //   [24]     log_flag:u8        (filled by apply_armor; 1 = stderr+logcat on)
    //   [25..32] reserved
    let blob_off = out.len();
    out.extend_from_slice(b"QVMP");
    let packed = pack_blob(blob);
    let mut len_buf = [0u8; 4];
    LittleEndian::write_u32(&mut len_buf, packed.len() as u32);
    out.extend_from_slice(&len_buf);
    out.extend_from_slice(&[0u8; 24]); // 16 rodata + 1 log + 7 reserved
    out.extend_from_slice(&packed);

    // ---- 3b. 嵌入 runtime cdylib + bootstrap ----
    let mut embedded_so_vaddr = 0u64;
    let mut embedded_so_len = 0u64;
    let mut bootstrap_vaddr = 0u64;
    let mut init_array_vaddr_new = 0u64;

    let new_segment_vaddr = new_vaddr_base;

    if let Some(so_bytes) = &opts.embed_runtime_so {
        // dlopen PLT must exist in main ELF. If not, bail loudly.
        let dlopen_plt = crate::bootstrap::find_dlopen_plt(&loaded.raw).ok_or_else(|| {
            RewriteError::Internal(
                "main ELF does not import dlopen — cannot embed runtime in single-file mode"
                    .into(),
            )
        })?;

        // Derive a per-build XOR key from ELF header bytes — keeps `strings`
        // / `grep` over the embedded runtime silent and the key trivially
        // recoverable from the live process (since it's stored in the
        // bootstrap stub literal).
        let mut key_bytes = [0u8; 8];
        for i in 0..8 {
            key_bytes[i] =
                loaded.raw[i] ^ loaded.raw.get(0x18 + i).copied().unwrap_or(0) ^ (0xA5 ^ i as u8);
        }
        let xor_key = u64::from_le_bytes(key_bytes);
        let so_encrypted = crate::bootstrap::xor_runtime(so_bytes, xor_key);

        // 8-byte align before bootstrap so its u64 literals load fine.
        while out.len() % 8 != 0 {
            out.push(0);
        }
        let bootstrap_file_off = out.len();
        let bootstrap_vaddr_local =
            new_segment_vaddr + (bootstrap_file_off - new_segment_off) as u64;

        let stub_len = crate::bootstrap::BOOTSTRAP_BIN.len();
        let embedded_so_file_off = bootstrap_file_off + stub_len;
        let embedded_so_vaddr_local =
            new_segment_vaddr + (embedded_so_file_off - new_segment_off) as u64;

        let stub_bytes = crate::bootstrap::patch_bootstrap(
            bootstrap_vaddr_local,
            embedded_so_vaddr_local,
            so_encrypted.len() as u64,
            dlopen_plt,
            xor_key,
        )?;
        out.extend_from_slice(&stub_bytes);
        out.extend_from_slice(&so_encrypted);

        embedded_so_vaddr = embedded_so_vaddr_local;
        embedded_so_len = so_encrypted.len() as u64;
        bootstrap_vaddr = bootstrap_vaddr_local;
    }

    // 对齐到页边界结束新 segment
    while (out.len() - new_segment_off) % page_align != 0 {
        out.push(0);
    }
    let new_segment_size = out.len() - new_segment_off;

    // ---- 4. 添加新 PT_LOAD program header（先把整个 phdr 复制到末尾再增加一条）----
    add_load_phdr(&mut out, new_segment_off, new_segment_vaddr, new_segment_size, page_align_u64)?;

    // ---- 4b. 改写 ELF e_entry 让 bootstrap 在 _start 之前跑 ----
    // (之前用 INIT_ARRAY[0] 劫持，但发现 dlopen 在主 exec 的 INIT_ARRAY 上下文
    // 会触发 bionic 栈金丝雀 abort —— 大概率某个 thread-local 状态还没准备好。
    // 改成 e_entry 劫持，bootstrap 在 NEEDED libs 的 init 都跑完之后、主 exec
    // 的 _start 之前执行，dlopen 在这个时机是安全的。)
    if bootstrap_vaddr != 0 {
        // Use INIT_ARRAY[0] hijack for diagnostic mode — confirms whether the
        // launcher actually goes through INIT_ARRAY (which dlopen-based execs do)
        // vs. e_entry/_start (which kernel exec does).
        init_array_vaddr_new = patch_init_array_hijack(
            &mut out, &loaded.raw, bootstrap_vaddr, page_align_u64,
            opts.shim_exit_diagnostic,
        )?;
    }

    // ---- 5. 在每个 region 的 patch_addr 写 trampoline 跳转 ----
    // BTI 兼容: 如果二进制启用了 ARMv8.5 Branch Target Identification (每个
    // indirect-call 目标必须有 `bti c/j/jc` 或 `paciasp` 等 PAC 指令), 用
    // 一条裸 `B trampoline` 覆盖函数入口时, 凡是通过 BLR/BR 到该函数的调用
    // 都会在落地那条 B 上触发 Branch Target Exception → kernel SIGILL.
    //
    // 解决: 用 2 条指令 patch — `bti jc` (HINT, allow both BR 和 BLR landing)
    // 后面跟 `B trampoline`. 函数入口至少 8 字节才能完整 patch; 否则 fallback
    // 单 `B trampoline` (BTI-less 二进制路径).
    let mut patched_entries = 0usize;
    if opts.write_entry_trampolines {
        // 判断原 ELF 是否带 BTI: 简单方法 — 看任何函数入口是否有 `bti c/j/jc`
        // 或 `paciasp/pacibsp` 指令. 一处即代表整个 .text 走 BTI 模式
        // (BTI 是 page-attribute, ld 通常全段一致).
        let bti_enabled = detect_bti_protection(&loaded.raw);
        let bti_jc_inst: u32 = 0xD50324DF; // BTI jc — allow both call/jump landing
        for (idx, region) in blob.regions.iter().enumerate() {
            let target_vaddr = new_segment_vaddr + (idx * 16) as u64;
            let file_off = match vaddr_to_file_off(&loaded.raw, region.patch_addr) {
                Some(o) => o,
                None => continue,
            };

            // 估算可以写多少字节: min(patch_len, 8 if BTI else 4)
            let avail = region.patch_len as usize;
            let want = if bti_enabled && avail >= 8 { 8 } else { 4 };
            if file_off + want > out.len() {
                continue;
            }

            let (bti_prefix_offset, b_inst_addr) = if want == 8 {
                // 第二条指令位置: patch_addr + 4
                (0usize, region.patch_addr + 4)
            } else {
                (0, region.patch_addr)
            };

            let rel = (target_vaddr as i64) - (b_inst_addr as i64);
            let b_inst = match encode_b(rel as i32) {
                Ok(v) => v,
                Err(_) => {
                    log::warn!(
                        "region {} patch_addr {:#x} 距离跳板 {:#x} 超过 B 范围，跳过 patch",
                        idx, region.patch_addr, target_vaddr
                    );
                    continue;
                }
            };

            if want == 8 {
                LittleEndian::write_u32(
                    &mut out[file_off + bti_prefix_offset..file_off + bti_prefix_offset + 4],
                    bti_jc_inst,
                );
                LittleEndian::write_u32(&mut out[file_off + 4..file_off + 8], b_inst);
            } else {
                LittleEndian::write_u32(&mut out[file_off..file_off + 4], b_inst);
            }
            patched_entries += 1;
        }
    }

    // ---- 4c. Add DT_NEEDED via DT_DEBUG slot replacement + .dynstr extension ----
    // (alternative to embed-runtime mode; lets the linker auto-load
    // libqvmp_runtime.so BEFORE main exec INIT_ARRAY runs, avoiding all
    // dlopen-from-INIT_ARRAY canary issues.)
    if let Some(dt_path) = &opts.dt_needed_path {
        add_dt_needed(&mut out, dt_path)?;
    }

    Ok((
        out,
        RewriteReport {
            embedded_so_vaddr,
            embedded_so_len,
            bootstrap_vaddr,
            init_array_vaddr: init_array_vaddr_new,
            patched_entries,
            trampoline_table_offset: trampoline_table_off as u64,
            blob_offset: blob_off as u64,
            new_segment_vaddr,
            new_segment_size: new_segment_size as u64,
        },
    ))
}

/// Add a `DT_NEEDED` dependency on `path` by:
///   1. Copying the current `.dynstr` into the new LOAD segment + appending
///      `path` + NUL terminator. New strtab is in RX mapped memory (linker
///      only reads strings, never writes).
///   2. Updating `DT_STRTAB` to point at the new strtab vaddr and `DT_STRSZ`
///      to the new size.
///   3. Repurposing the existing `DT_DEBUG` entry (tag=0x15, always present
///      in PIEs, optional / debugger-only) to `DT_NEEDED` (tag=0x01) with
///      value = offset of `path` within the new strtab.
/// This avoids relocating `.dynamic` itself (it stays in its original RW
/// LOAD where the linker can still write to it).
fn add_dt_needed(out: &mut Vec<u8>, needed_path: &str) -> Result<()> {
    use byteorder::{ByteOrder, LittleEndian};
    use goblin::elf::Elf;
    use goblin::elf::dynamic::{DT_DEBUG, DT_NEEDED, DT_STRSZ, DT_STRTAB};

    // Parse and clone needed values, then drop the parse so `out` is freely mutable.
    let (strtab_vaddr, strsz, dyn_off, dyn_size) = {
        let elf = Elf::parse(out).map_err(|e| RewriteError::Parse(e.to_string()))?;
        let dynamic = elf
            .dynamic
            .as_ref()
            .ok_or_else(|| RewriteError::Internal("missing PT_DYNAMIC".into()))?;
        let mut strtab_val: Option<u64> = None;
        let mut strsz_val: Option<u64> = None;
        for d in &dynamic.dyns {
            if d.d_tag == DT_STRTAB {
                strtab_val = Some(d.d_val);
            } else if d.d_tag == DT_STRSZ {
                strsz_val = Some(d.d_val);
            }
        }
        let strtab_vaddr =
            strtab_val.ok_or_else(|| RewriteError::Internal("DT_STRTAB missing".into()))?;
        let strsz = strsz_val.ok_or_else(|| RewriteError::Internal("DT_STRSZ missing".into()))?
            as usize;
        let dyn_ph = elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == goblin::elf::program_header::PT_DYNAMIC)
            .ok_or_else(|| RewriteError::Internal("PT_DYNAMIC not found".into()))?;
        let dyn_off = dyn_ph.p_offset as usize;
        let dyn_size = dyn_ph.p_filesz as usize;
        (strtab_vaddr, strsz, dyn_off, dyn_size)
    };

    // Read existing .dynstr bytes from the file (identity-mapped in LOAD #2)
    let strtab_file_off = vaddr_to_file_off(out, strtab_vaddr)
        .ok_or_else(|| RewriteError::Internal("DT_STRTAB vaddr not in PT_LOAD".into()))?;
    if strtab_file_off + strsz > out.len() {
        return Err(RewriteError::Internal(".dynstr bounds invalid".into()));
    }
    let original_strtab = out[strtab_file_off..strtab_file_off + strsz].to_vec();

    // Append new strtab to file in the new LOAD segment area (identity-mapped),
    // 8-byte aligned. New string goes at offset (old strsz) within new strtab.
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let new_strtab_file_off = out.len();
    let new_string_offset_in_strtab = original_strtab.len();
    out.extend_from_slice(&original_strtab);
    out.extend_from_slice(needed_path.as_bytes());
    out.push(0);
    let new_strsz = original_strtab.len() + needed_path.len() + 1;
    let new_strtab_vaddr = new_strtab_file_off as u64; // identity-mapped

    // Page-align + extend last LOAD's filesz/memsz so the new strtab is mapped.
    let page = 0x4000usize;
    let aligned = (out.len() + page - 1) & !(page - 1);
    while out.len() < aligned {
        out.push(0);
    }
    extend_last_load_to_file_end(out)?;

    // Walk .dynamic, patch DT_STRTAB and DT_STRSZ, and repurpose DT_DEBUG.
    let mut replaced_debug = false;
    let mut i = 0;
    while i + 16 <= dyn_size {
        let p = dyn_off + i;
        let tag = LittleEndian::read_u64(&out[p..p + 8]);
        if tag == DT_STRTAB {
            LittleEndian::write_u64(&mut out[p + 8..p + 16], new_strtab_vaddr);
        } else if tag == DT_STRSZ {
            LittleEndian::write_u64(&mut out[p + 8..p + 16], new_strsz as u64);
        } else if tag == DT_DEBUG && !replaced_debug {
            LittleEndian::write_u64(&mut out[p..p + 8], DT_NEEDED);
            LittleEndian::write_u64(&mut out[p + 8..p + 16], new_string_offset_in_strtab as u64);
            replaced_debug = true;
        }
        i += 16;
    }
    if !replaced_debug {
        return Err(RewriteError::Internal("DT_DEBUG slot not found".into()));
    }

    Ok(())
}

/// Hijack ELF `e_entry` to point at a freshly-emitted shim that calls
/// `bootstrap` and then tail-jumps to the original `_start`. The shim runs
/// **before** the main exec's INIT_ARRAY (which is invoked from inside
/// `_start` → `__libc_init`), so dlopen during bootstrap is safe.
///
/// Returns the shim's runtime vaddr (== new `e_entry`).
fn patch_e_entry_hijack(
    out: &mut Vec<u8>,
    orig_elf: &[u8],
    bootstrap_vaddr: u64,
    page_align: u64,
    exit_after_bootstrap: bool,
) -> Result<u64> {
    use byteorder::{ByteOrder, LittleEndian};

    let orig_entry = LittleEndian::read_u64(&orig_elf[0x18..0x20]);
    if orig_entry == 0 {
        return Err(RewriteError::Internal("orig e_entry is 0".into()));
    }

    // 4-byte align (need to be 4-byte aligned for ARM64 instructions)
    while out.len() % 4 != 0 {
        out.push(0);
    }
    let shim_file_off = out.len();
    // Find the latest PT_LOAD to compute the shim's vaddr (identity-mapped).
    let new_elf = goblin::elf::Elf::parse(out)
        .map_err(|e| RewriteError::Parse(e.to_string()))?;
    let mut last_load: Option<&goblin::elf::ProgramHeader> = None;
    for ph in &new_elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD
            && last_load.map_or(true, |p| ph.p_vaddr > p.p_vaddr)
        {
            last_load = Some(ph);
        }
    }
    let last = last_load.ok_or_else(|| RewriteError::Internal("no PT_LOAD".into()))?;
    let shim_vaddr = last.p_vaddr + (shim_file_off - last.p_offset as usize) as u64;

    // shim:
    //   stp x29, x30, [sp, #-16]!     ; preserve LR (kernel sets x30=0 but
    //                                   bionic _start expects x30 not used so
    //                                   conservatively save anyway)
    //   bl bootstrap                  ; do dlopen of embedded runtime
    //   ldp x29, x30, [sp], #16
    //   b orig_e_entry                ; tail-jump to libc _start
    let mut emit = |w: u32| {
        let mut b = [0u8; 4];
        LittleEndian::write_u32(&mut b, w);
        out.extend_from_slice(&b);
    };
    emit(0xa9bf7bfd); // STP X29,X30,[SP,#-16]!
    let bl_pc = shim_vaddr + 4;
    let bl_imm26 = ((bootstrap_vaddr as i64 - bl_pc as i64) / 4) & 0x3ff_ffff;
    emit(0x94_00_00_00u32 | bl_imm26 as u32);
    emit(0xa8c17bfd); // LDP X29,X30,[SP],#16
    if exit_after_bootstrap {
        // SYS_exit_group(x0) — diagnostic mode: x0 holds bootstrap's stage code,
        // and we exit the process with that as the exit code so MT 管理器's
        // process-ended dialog displays it.
        emit(0xd2800ba8); // MOV X8, #94 (SYS_exit_group)
        emit(0xd4000001); // SVC #0
        emit(0xd503201f); // NOP (alignment, never reached)
    } else {
        // Skip the FIRST 4 bytes of orig_entry (we've patched them to
        // `b shim_vaddr` below — jumping back to orig_entry would infinite
        // loop). For the user's binary, _start[0] is BTI C (a no-op-like
        // landing pad) which is safe to skip; the rest of _start continues
        // setting up argc/argv and calling __libc_init.
        let b_pc = shim_vaddr + 12;
        let b_target = orig_entry + 4;
        let b_imm26 = ((b_target as i64 - b_pc as i64) / 4) & 0x3ff_ffff;
        emit(0x14_00_00_00u32 | b_imm26 as u32);
    }

    // Page-align tail and extend last LOAD's filesz/memsz.
    let page = page_align as usize;
    let aligned_end = (out.len() + page - 1) & !(page - 1);
    while out.len() < aligned_end {
        out.push(0);
    }
    extend_last_load_to_file_end(out)?;

    // Patch ELF header's e_entry to shim_vaddr.
    LittleEndian::write_u64(&mut out[0x18..0x20], shim_vaddr);

    // BELT + SUSPENDERS: also patch the first 4 bytes of the ORIGINAL
    // `_start` (orig_entry vaddr) to `B shim_vaddr`. Some Android launchers
    // (MT 管理器, certain proot wrappers, dlopen-based execs) appear to NOT
    // use e_entry from the ELF header for ET_DYN PIE binaries — they jump
    // to whatever symbol `_start` points to, or use a cached entry. Patching
    // the first instruction at orig_entry redirects those paths through our
    // shim as well. We just need to make sure `b shim_vaddr - orig_entry`
    // fits in B-imm26 (±128 MB), which is true for our layout.
    if let Some(orig_entry_file_off) = vaddr_to_file_off(out, orig_entry) {
        let rel = (shim_vaddr as i64) - (orig_entry as i64);
        if rel % 4 == 0 && rel >= -(1 << 27) && rel < (1 << 27) {
            let imm26 = ((rel / 4) as u32) & 0x03ff_ffff;
            let b_inst = 0x14_00_00_00u32 | imm26;
            if orig_entry_file_off + 4 <= out.len() {
                LittleEndian::write_u32(
                    &mut out[orig_entry_file_off..orig_entry_file_off + 4],
                    b_inst,
                );
            }
        }
    }

    Ok(shim_vaddr)
}

/// Hijack INIT_ARRAY[0] in place — modify its R_AARCH64_RELATIVE relocation's
/// `r_addend` to point at a wrapper that does our bootstrap then tail-calls
/// the original first init function. This avoids relocating .init_array
/// itself (which would require chasing every relocation that targets it) and
/// keeps .dynamic untouched.
///
/// Layout written into `out`:
///   [bootstrap stub][embedded .so][...padding...][wrapper stub]
/// The wrapper, freshly minted here, calls bootstrap and then jumps to the
/// original first-init function (whose address is read out of the existing
/// relocation's addend).
///
/// Returns vaddr of the wrapper (== new addend value).
fn patch_init_array_hijack(
    out: &mut Vec<u8>,
    orig_elf: &[u8],
    bootstrap_vaddr: u64,
    page_align: u64,
    exit_after_bootstrap: bool,
) -> Result<u64> {
    use goblin::elf::Elf;
    use goblin::elf::dynamic::{DT_INIT_ARRAY, DT_INIT_ARRAYSZ};
    use goblin::elf::reloc::R_AARCH64_RELATIVE;

    let elf = Elf::parse(orig_elf).map_err(|e| RewriteError::Parse(e.to_string()))?;
    let dynamic = elf
        .dynamic
        .as_ref()
        .ok_or_else(|| RewriteError::Internal("missing PT_DYNAMIC".into()))?;

    let mut init_array_vaddr: Option<u64> = None;
    let mut init_array_size: Option<u64> = None;
    for d in &dynamic.dyns {
        match d.d_tag {
            DT_INIT_ARRAY => init_array_vaddr = Some(d.d_val),
            DT_INIT_ARRAYSZ => init_array_size = Some(d.d_val),
            _ => {}
        }
    }
    let ia_vaddr =
        init_array_vaddr.ok_or_else(|| RewriteError::Internal("DT_INIT_ARRAY missing".into()))?;
    let ia_size = init_array_size.unwrap_or(8);
    // Hijack INIT_ARRAY[0] (first entry, runs first when linker calls
    // INIT_ARRAY entries). Previously we used the last entry, but if a
    // launcher only runs SOME init array entries before the binary's
    // patched function gets hit, [0] is the safest position.
    let target_entry_vaddr = ia_vaddr;

    // Find the .rela.dyn relocation whose r_offset == target_entry_vaddr
    // and which is R_AARCH64_RELATIVE (= 1027 on aarch64).
    let mut rela_file_off: Option<usize> = None;
    let mut original_addend: i64 = 0;
    {
        // .rela.dyn is referenced from PT_DYNAMIC (DT_RELA / DT_RELASZ); use
        // goblin's parsed view to iterate, but we need the FILE offset of the
        // matching entry to patch it.
        let rela_section = elf.section_headers.iter().find(|sh| {
            elf.shdr_strtab
                .get_at(sh.sh_name)
                .map_or(false, |n| n == ".rela.dyn")
        });
        let rela_off = rela_section
            .map(|sh| sh.sh_offset as usize)
            .ok_or_else(|| RewriteError::Internal(".rela.dyn missing".into()))?;
        let rela_sz = rela_section.map(|sh| sh.sh_size as usize).unwrap_or(0);
        let entsize = 24usize; // Elf64_Rela: r_offset(8) + r_info(8) + r_addend(8)
        let mut i = 0;
        while i + entsize <= rela_sz {
            let p = rela_off + i;
            let r_offset = LittleEndian::read_u64(&orig_elf[p..p + 8]);
            let r_info = LittleEndian::read_u64(&orig_elf[p + 8..p + 16]);
            let r_addend = LittleEndian::read_i64(&orig_elf[p + 16..p + 24]);
            let r_type = (r_info & 0xffff_ffff) as u32;
            if r_offset == target_entry_vaddr && r_type == R_AARCH64_RELATIVE {
                rela_file_off = Some(p);
                original_addend = r_addend;
                break;
            }
            i += entsize;
        }
    }
    let rela_p = rela_file_off
        .ok_or_else(|| RewriteError::Internal("no R_RELATIVE for INIT_ARRAY[0]".into()))?;

    // Build a small wrapper:
    //   stp x29,x30,[sp,#-16]!
    //   bl bootstrap
    //   ldp x29,x30,[sp],#16
    //   b orig_init_func
    while out.len() % 4 != 0 {
        out.push(0);
    }
    let wrapper_file_off = out.len();
    // Determine current last LOAD's vaddr/file_off to compute wrapper's vaddr.
    let new_elf = Elf::parse(out).map_err(|e| RewriteError::Parse(e.to_string()))?;
    let mut last_load: Option<&goblin::elf::ProgramHeader> = None;
    for ph in &new_elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD
            && last_load.map_or(true, |p| ph.p_vaddr > p.p_vaddr)
        {
            last_load = Some(ph);
        }
    }
    let last = last_load.ok_or_else(|| RewriteError::Internal("no PT_LOAD".into()))?;
    let last_seg_file = last.p_offset as usize;
    let last_seg_vaddr = last.p_vaddr;
    let wrapper_vaddr = last_seg_vaddr + (wrapper_file_off - last_seg_file) as u64;

    // Encode the 4 instructions.
    let mut emit = |w: u32| {
        let mut b = [0u8; 4];
        LittleEndian::write_u32(&mut b, w);
        out.extend_from_slice(&b);
    };
    emit(0xa9bf7bfd); // STP X29,X30,[SP,#-16]!
    // BL bootstrap (PC = wrapper_vaddr + 4)
    let bl_pc = wrapper_vaddr + 4;
    let bl_imm26 = ((bootstrap_vaddr as i64 - bl_pc as i64) / 4) & 0x3ff_ffff;
    emit(0x94_00_00_00u32 | bl_imm26 as u32);
    emit(0xa8c17bfd); // LDP X29,X30,[SP],#16
    if exit_after_bootstrap {
        // Diagnostic: exit_group(x0 = bootstrap return value)
        emit(0xd2800ba8); // MOV X8, #93 (SYS_exit)
        emit(0xd4000001); // SVC #0
    } else {
        // B orig_init_func (PC = wrapper_vaddr + 12)
        let b_pc = wrapper_vaddr + 12;
        let b_imm26 = ((original_addend - b_pc as i64) / 4) & 0x3ff_ffff;
        emit(0x14_00_00_00u32 | b_imm26 as u32);
    }

    // Page-align tail and extend the last PT_LOAD's filesz/memsz to cover
    // the wrapper.
    let page = page_align as usize;
    let aligned_end = (out.len() + page - 1) & !(page - 1);
    while out.len() < aligned_end {
        out.push(0);
    }
    extend_last_load_to_file_end(out)?;

    // Patch the relocation's r_addend to wrapper_vaddr.
    LittleEndian::write_u64(&mut out[rela_p + 16..rela_p + 24], wrapper_vaddr);

    Ok(wrapper_vaddr)
}

/// Bump the last PT_LOAD's filesz/memsz to reach the current end of `out`.
/// Used after appending content past the original new-LOAD boundary.
fn extend_last_load_to_file_end(out: &mut Vec<u8>) -> Result<()> {
    use goblin::elf::Elf;
    let elf = Elf::parse(out).map_err(|e| RewriteError::Parse(e.to_string()))?;
    let phoff = elf.header.e_phoff as usize;
    let phentsize = elf.header.e_phentsize as usize;
    let phnum = elf.header.e_phnum as usize;
    let mut best_idx: Option<usize> = None;
    let mut best_vaddr = 0u64;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let p_type = LittleEndian::read_u32(&out[off..off + 4]);
        if p_type != goblin::elf::program_header::PT_LOAD {
            continue;
        }
        let p_vaddr = LittleEndian::read_u64(&out[off + 16..off + 24]);
        if best_idx.is_none() || p_vaddr > best_vaddr {
            best_idx = Some(i);
            best_vaddr = p_vaddr;
        }
    }
    let i = best_idx
        .ok_or_else(|| RewriteError::Internal("no PT_LOAD to extend".into()))?;
    let off = phoff + i * phentsize;
    let p_offset = LittleEndian::read_u64(&out[off + 8..off + 16]);
    let new_size = (out.len() as u64) - p_offset;
    LittleEndian::write_u64(&mut out[off + 32..off + 40], new_size); // p_filesz
    LittleEndian::write_u64(&mut out[off + 40..off + 48], new_size); // p_memsz
    Ok(())
}

/// 找到所有 PT_LOAD segment 中最大的 vaddr+memsz，向上对齐到与原有 LOAD
/// 一致的 page 大小。返回 (aligned_vaddr, page_size)。
///
/// 关键：Android 14+ 在 Pixel 6+ / 高通新 SoC 上**默认 16KB 页**。原 binary 通常
/// 编译时按 16KB 对齐 (LOAD `p_align=0x4000`)，新 LOAD 必须用相同对齐，否则
/// 16KB 页系统的 mmap 会拒绝（与上一段的最后一页相冲），bionic 给出
/// 通用 "Android only supports PIE" 错误。
fn next_load_vaddr(elf_bytes: &[u8]) -> Result<(u64, u64)> {
    use goblin::elf::Elf;
    let elf = Elf::parse(elf_bytes).map_err(|e| RewriteError::Parse(e.to_string()))?;
    let mut max_end = 0u64;
    let mut max_align = 0x1000u64;
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD {
            let end = ph.p_vaddr + ph.p_memsz;
            if end > max_end {
                max_end = end;
            }
            if ph.p_align > max_align {
                max_align = ph.p_align;
            }
        }
    }
    let mask = max_align - 1;
    let aligned = (max_end + mask) & !mask;
    Ok((aligned, max_align))
}

/// 把 patch_addr (虚拟地址) 转成原 ELF 文件内的字节偏移。
/// 嗅探 ELF 是否启用 ARMv8.5 BTI 保护.
///
/// 启发式: 扫前若干条 .text 指令, 看到任何 `bti c/j/jc` 或 `paciasp/pacibsp`
/// 即认为整段开启了 GP (Guarded Page) 属性, 所有 indirect-call 落地点必须
/// 是 BTI / PAC 指令. 这是 ld + binutils 在链接器侧识别 `.note.gnu.property`
/// 后给每段加的 PROT_BTI.
///
/// 准确判定要查 PT_GNU_PROPERTY note 的 AArch64 Feature 1 bit, 但实践上
/// 函数入口处看一眼就够 — false positive 几乎不存在.
fn detect_bti_protection(elf_bytes: &[u8]) -> bool {
    use byteorder::{ByteOrder, LittleEndian};
    use goblin::elf::program_header::{PF_X, PT_LOAD};
    use goblin::elf::Elf;

    let elf = match Elf::parse(elf_bytes) {
        Ok(e) => e,
        Err(_) => return false,
    };
    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD || (ph.p_flags & PF_X) == 0 {
            continue;
        }
        let off = ph.p_offset as usize;
        let len = ph.p_filesz as usize;
        if off + len > elf_bytes.len() {
            continue;
        }
        let mut i = 0;
        while i + 4 <= len.min(0x4000) {
            let inst = LittleEndian::read_u32(&elf_bytes[off + i..off + i + 4]);
            // BTI 编码: 0xD503_24XX 其中 XX 高 3 位 = 001 (c=0x5F, j=0x9F, jc=0xDF)
            // PAC: 0xD503_233F (paciasp), 0xD503_237F (pacibsp), 0xD503_2BBF (autiasp).
            // 都属于 HINT 系列 0xD503_2X 1F 共性.
            if inst == 0xD503245F   // bti c
                || inst == 0xD503249F // bti j
                || inst == 0xD50324DF // bti jc
                || inst == 0xD503233F // paciasp
                || inst == 0xD503237F // pacibsp
            {
                return true;
            }
            i += 4;
        }
    }
    false
}

fn vaddr_to_file_off(elf_bytes: &[u8], vaddr: u64) -> Option<usize> {
    use goblin::elf::Elf;
    let elf = Elf::parse(elf_bytes).ok()?;
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD
            && vaddr >= ph.p_vaddr
            && vaddr < ph.p_vaddr + ph.p_filesz
        {
            return Some((ph.p_offset + (vaddr - ph.p_vaddr)) as usize);
        }
    }
    None
}

/// 复制原 program header table 到文件末尾，并追加一个新的 PT_LOAD 条目。
/// 同时把 ELF header 中的 `e_phoff` / `e_phnum` 更新指向新位置。
///
/// 关键点（早期版本踩坑）：
/// - PHDR table 移动后，原 `PT_PHDR` 条目里 `p_offset` / `p_vaddr` / `p_filesz`
///   指向旧位置；Android linker64 的 `FindPhdr()` 依赖该条目，链接器报
///   "Could not find a PHDR: broken executable" 然后 abort 即源于此。必须把
///   `PT_PHDR` 条目改写到新位置。
/// - 新 PHDR table 必须落在某个 PT_LOAD 的 file/vaddr 范围内（否则它根本不会
///   被 mmap 到内存里，PT_PHDR.vaddr 验证失败）。我们把新 PHDR table 直接接在
///   新 LOAD segment 后面，并把该 segment 的 `p_filesz`/`p_memsz` 延伸覆盖之。
fn add_load_phdr(
    out: &mut Vec<u8>,
    seg_file_off: usize,
    seg_vaddr: u64,
    _seg_size: usize,
    page_align: u64,
) -> Result<()> {
    use goblin::elf::Elf;
    use goblin::elf::program_header::{PT_LOAD, PT_PHDR};
    let elf = Elf::parse(&out[..]).map_err(|e| RewriteError::Parse(e.to_string()))?;
    if !elf.is_64 {
        return Err(RewriteError::Unsupported);
    }
    let phentsize = elf.header.e_phentsize as usize;
    let old_phoff = elf.header.e_phoff as usize;
    let old_phnum = elf.header.e_phnum as usize;
    let mut phdr_bytes = out[old_phoff..old_phoff + old_phnum * phentsize].to_vec();

    let new_phnum = old_phnum + 1;
    let new_phdr_total = new_phnum * phentsize;

    // 把 PHDR table 放在新 LOAD segment 内部、紧接现有 trampolines+blob 之后。
    // 对齐到 8 字节就够了（PHDR 自身要求 alignof(Elf64_Phdr) = 8）；不需要页对齐。
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let new_phoff = out.len();

    // 新 PHDR table 的虚拟地址：落在新 LOAD segment 内部
    let new_phdr_vaddr = seg_vaddr + (new_phoff as u64 - seg_file_off as u64);

    // 改写 phdr_bytes 里的 PT_PHDR 条目
    for i in 0..old_phnum {
        let off = i * phentsize;
        let p_type = LittleEndian::read_u32(&phdr_bytes[off..off + 4]);
        if p_type == PT_PHDR {
            LittleEndian::write_u64(&mut phdr_bytes[off + 8..off + 16], new_phoff as u64);
            LittleEndian::write_u64(&mut phdr_bytes[off + 16..off + 24], new_phdr_vaddr);
            LittleEndian::write_u64(&mut phdr_bytes[off + 24..off + 32], new_phdr_vaddr);
            LittleEndian::write_u64(&mut phdr_bytes[off + 32..off + 40], new_phdr_total as u64);
            LittleEndian::write_u64(&mut phdr_bytes[off + 40..off + 48], new_phdr_total as u64);
            break;
        }
    }

    // 1) 写 PHDR table（旧 phdrs + 新 LOAD entry）
    // 2) 向上 page-pad 文件，让 PHDR table 完整落在 page-aligned 段内
    // 3) 新 LOAD entry 的 filesz/memsz 延伸覆盖 padding 后整个范围
    let mask = (page_align - 1) as usize;
    let raw_end = new_phoff + new_phdr_total;
    let aligned_end = (raw_end + mask) & !mask;
    let extended_seg_size = aligned_end - seg_file_off;
    let mut entry = [0u8; 56];
    LittleEndian::write_u32(&mut entry[0..4], PT_LOAD);
    LittleEndian::write_u32(&mut entry[4..8], 0x4 | 0x1); // PF_R | PF_X
    LittleEndian::write_u64(&mut entry[8..16], seg_file_off as u64);
    LittleEndian::write_u64(&mut entry[16..24], seg_vaddr);
    LittleEndian::write_u64(&mut entry[24..32], seg_vaddr);
    LittleEndian::write_u64(&mut entry[32..40], extended_seg_size as u64);
    LittleEndian::write_u64(&mut entry[40..48], extended_seg_size as u64);
    LittleEndian::write_u64(&mut entry[48..56], page_align);
    if entry.len() != phentsize {
        return Err(RewriteError::Internal(format!(
            "phentsize 不匹配: {} vs {}",
            phentsize,
            entry.len()
        )));
    }

    // (1) PHDR table goes here, at new_phoff
    out.extend_from_slice(&phdr_bytes);
    out.extend_from_slice(&entry);
    // (2) page-pad to aligned_end so the new LOAD's filesz lands on a page boundary
    while out.len() < aligned_end {
        out.push(0);
    }

    // 更新 ELF header：e_phoff (offset 0x20, 8B) + e_phnum (offset 0x38, 2B)
    LittleEndian::write_u64(&mut out[0x20..0x28], new_phoff as u64);
    LittleEndian::write_u16(&mut out[0x38..0x3A], new_phnum as u16);
    Ok(())
}
