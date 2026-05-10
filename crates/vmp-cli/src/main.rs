//! vmp CLI
//!
//! 一键流水线：加载二进制 → 选 lift 目标 → lift 到 IR → encode 字节码 → 打包 stub blob。
//!
//! 当前 CLI 提供两条命令：
//!   `vmp protect`  把目标二进制全部用户函数 lift+vmp，输出 `.qvmp` 包文件。
//!   `vmp run`      读取 `.qvmp` 并模拟执行第一个 region（用于功能性测试）。
//!
//! 真正的「写回宿主二进制」（patch + 嵌入 stub + 重排 ELF/PE 段）属于 packer 后端，
//! 留待与 vmp-loader 一起扩展，本骨架已经把数据结构铺好。

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::path::PathBuf;
use vmp_codegen::{resolve_program, CodeGen, FunctionRegion};
use vmp_core::{ProtectConfig, ProtectLevel};
use vmp_isa::IsaRandomizer;
use vmp_stub::{pack_blob, unpack_blob, StubBlob, StubRegion};

#[derive(Debug, Parser)]
#[command(name = "vmp", about = "Qsafe VMP — ARM64-first 模块化 VMP 加壳器", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// 日志级别 (error/warn/info/debug/trace)
    #[arg(long, default_value = "info")]
    log: String,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// 对二进制做 VMP 保护，输出 stub blob
    Protect {
        /// 输入二进制文件
        input: PathBuf,
        /// 输出 .qvmp 文件
        #[arg(short, long)]
        output: PathBuf,
        /// 保护强度
        #[arg(long, default_value = "standard")]
        level: Level,
        /// 随机种子（默认随机；指定可复现构建）
        #[arg(long)]
        seed: Option<u64>,
        /// 仅保护这些函数（多次指定 / 逗号分隔）
        #[arg(long)]
        only: Vec<String>,
        /// 排除这些函数
        #[arg(long)]
        exclude: Vec<String>,
        /// 跳过 lift 报告含 skipped/Trap 的函数（保留原生执行，避免运行时 Trap）
        #[arg(long, default_value_t = true)]
        skip_traps: bool,
        /// 函数大小上限（字节）；超出则跳过 lift（默认 0 = 无限制）
        #[arg(long, default_value_t = 0u64)]
        max_func_size: u64,
    },
    /// 直接 lift 一段裸字节码（hex 或文件），用于调试 lifter
    Lift {
        /// 输入文件（二进制）；和 --hex 二选一
        #[arg(long)]
        file: Option<PathBuf>,
        /// 直接给一个 hex 字符串
        #[arg(long)]
        hex: Option<String>,
        /// 起始虚拟地址
        #[arg(long, default_value_t = 0x4000_0000)]
        base: u64,
        /// 架构
        #[arg(long, default_value = "arm64")]
        arch: ArchArg,
    },
    /// 模拟执行 .qvmp blob 的指定 region
    Run {
        blob: PathBuf,
        #[arg(long, default_value_t = 0)]
        region: usize,
        /// 入参 v0..v7（最多 8 个）
        #[arg(long)]
        arg: Vec<u64>,
    },
    /// 打印 .qvmp blob 的元信息
    Inspect { blob: PathBuf },
    /// 把 .qvmp blob 嵌入原 ELF / .so，输出 in-place 修改后的二进制（带跳板）
    Rewrite {
        /// 原始可执行 ELF 或 .so
        input: PathBuf,
        /// 已 protect 的 .qvmp 文件
        blob: PathBuf,
        /// 输出新 ELF 路径
        #[arg(short, long)]
        output: PathBuf,
        /// 是否在原 .text 写跳板（默认开；仅嵌入 blob 不写跳板时关闭）
        #[arg(long, value_parser = clap::value_parser!(bool), num_args = 0..=1, default_value_t = true, default_missing_value = "true")]
        write_trampolines: bool,
        /// 段名 / 符号名剥离 (.shstrtab / .strtab 置 0)
        #[arg(long, value_parser = clap::value_parser!(bool), num_args = 0..=1, default_value_t = true, default_missing_value = "true")]
        strip_names: bool,
        /// payload 二次加密（依赖 ELF header 派生 key）
        #[arg(long, value_parser = clap::value_parser!(bool), num_args = 0..=1, default_value_t = true, default_missing_value = "true")]
        xor_payload: bool,
        /// 加密 .rodata（运行时由 libqvmp_runtime.so 在 .init_array 解密）
        #[arg(long, value_parser = clap::value_parser!(bool), num_args = 0..=1, default_value_t = true, default_missing_value = "true")]
        encrypt_rodata: bool,
        /// 烧录日志开关 (--log on / --log off)；运行时直接读 QVMP 头字节，无 env var
        #[arg(long, default_value = "off")]
        log: String,
        /// 嵌入 libqvmp_runtime.so 的路径 → 单文件可执行（无需独立 .so 文件）
        #[arg(long)]
        embed_runtime: Option<PathBuf>,
    },
    /// 列出 .a 静态库内的 .o 成员（用于 batch protect 准备）
    ArList { archive: PathBuf },
}

#[derive(Debug, Clone, ValueEnum)]
enum Level {
    Light,
    Standard,
    Heavy,
    Paranoid,
}

#[derive(Debug, Clone, ValueEnum)]
enum ArchArg {
    Arm64,
    X86_64,
}

/// 从 ELF 字节流抽取所有非可执行的 PT_LOAD 段（.rodata / .data / .bss），
/// 转成 DataSegment 给 dispatch_vm 启动时映射。
fn extract_data_segments(elf_bytes: &[u8], out: &mut Vec<vmp_stub::DataSegment>) {
    use goblin::elf::program_header::{PF_W, PF_X, PT_LOAD};
    use goblin::elf::Elf;
    let elf = match Elf::parse(elf_bytes) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        if (ph.p_flags & PF_X) != 0 {
            // 可执行段（.text）— 由 VM lift 处理，不需要原样映射
            continue;
        }
        let file_off = ph.p_offset as usize;
        let file_sz = ph.p_filesz as usize;
        let mem_sz = ph.p_memsz as usize;
        if file_off + file_sz > elf_bytes.len() {
            continue;
        }
        let mut bytes = elf_bytes[file_off..file_off + file_sz].to_vec();
        // .bss 部分（mem_sz > file_sz）补 0
        if mem_sz > file_sz {
            bytes.resize(mem_sz, 0);
        }
        let prot = 0x1u8 | if (ph.p_flags & PF_W) != 0 { 0x2 } else { 0 };
        out.push(vmp_stub::DataSegment {
            vaddr: ph.p_vaddr,
            bytes,
            prot,
        });
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    std::env::set_var("RUST_LOG", &cli.log);
    env_logger::init();

    match cli.cmd {
        Cmd::Protect { input, output, level, seed, only, exclude, skip_traps, max_func_size } => {
            let bytes = fs::read(&input).with_context(|| format!("读取 {}", input.display()))?;
            let obj = vmp_loader::load(bytes)?;
            log::info!(
                "已加载 {:?} arch={} 函数符号={} 代码段={}",
                obj.format,
                obj.arch,
                obj.symbols.len(),
                obj.code.len()
            );

            let proto_level = match level {
                Level::Light => ProtectLevel::Light,
                Level::Standard => ProtectLevel::Standard,
                Level::Heavy => ProtectLevel::Heavy,
                Level::Paranoid => ProtectLevel::Paranoid,
            };
            let mut cfg = ProtectConfig::from_level(proto_level);
            if let Some(s) = seed {
                cfg.seed = s;
            }
            cfg.include_funcs.extend(only);
            cfg.exclude_funcs.extend(exclude);

            let spec = IsaRandomizer::new(cfg.seed, cfg.handler_duplication, cfg.encrypt_bytecode).build();
            log::info!("ISA 指纹: {}", hex::encode(spec.fingerprint));

            // 第一遍：lift 每个候选函数到 IR（branch imm 仍是绝对地址）。
            let mut funcs: Vec<FunctionRegion> = Vec::new();
            let mut skipped_size = 0usize;
            let mut skipped_traps = 0usize;
            for sym in &obj.symbols {
                if !cfg.exclude_funcs.is_empty() && cfg.exclude_funcs.iter().any(|n| n == &sym.name) {
                    continue;
                }
                if !cfg.include_funcs.is_empty() && !cfg.include_funcs.iter().any(|n| n == &sym.name) {
                    continue;
                }
                if max_func_size > 0 && sym.size > max_func_size {
                    skipped_size += 1;
                    continue;
                }
                let region = match obj.code.iter().find(|r| r.contains(sym.vaddr)) {
                    Some(r) => r,
                    None => continue,
                };
                let off = (sym.vaddr - region.vaddr) as usize;
                let end = off + sym.size as usize;
                if end > region.bytes.len() {
                    continue;
                }
                let func_bytes = &region.bytes[off..end];

                match vmp_arch::lift(obj.arch, func_bytes, sym.vaddr) {
                    Ok(lifted) => {
                        log::debug!(
                            "lift {} @ {:#x}  in={} out_ir={} skipped={} notes={}",
                            sym.name,
                            sym.vaddr,
                            lifted.report.total_input,
                            lifted.ir.len(),
                            lifted.report.skipped,
                            lifted.report.notes.len()
                        );
                        if lifted.report.skipped > 0
                            && (skip_traps || proto_level == ProtectLevel::Paranoid)
                        {
                            skipped_traps += 1;
                            continue;
                        }
                        funcs.push(FunctionRegion {
                            name: sym.name.clone(),
                            vaddr: sym.vaddr,
                            size: sym.size,
                            ir: lifted.ir,
                            native_to_ir: lifted.native_to_ir,
                        });
                    }
                    Err(e) => log::warn!("lift 失败 {}: {}", sym.name, e),
                }
            }
            log::info!(
                "lift summary: kept={} skipped_traps={} skipped_size={} (of {} candidates)",
                funcs.len(),
                skipped_traps,
                skipped_size,
                obj.symbols.len()
            );

            // 第二遍：全局多函数解析 —— BL <另一个被保护函数> 转为 CallRegion，
            // 函数内部分支转 IR 索引，无法解析的目标占位 Trap。
            let resolve_report = resolve_program(&mut funcs);
            log::info!(
                "branch resolve: intra={} cross_region={} unresolved={}",
                resolve_report.intra_branches,
                resolve_report.cross_region_calls,
                resolve_report.unresolved
            );

            // 第三遍：每个 region 独立 codegen，用 region_idx 作 IV salt。
            let mut pool: Vec<u8> = Vec::new();
            let mut regions: Vec<StubRegion> = Vec::new();
            for (region_idx, func) in funcs.iter().enumerate() {
                let mut cg = CodeGen::new(
                    &spec,
                    cfg.seed.wrapping_add(func.vaddr),
                    if cfg.insert_junk { 25 } else { 0 },
                    cfg.handler_duplication,
                )
                .with_iv_salt(region_idx as u64);
                let bc = cg.encode(&func.ir)?;
                let bc_offset = pool.len();
                pool.extend_from_slice(&bc);
                regions.push(StubRegion {
                    patch_addr: func.vaddr,
                    patch_len: func.size as u32,
                    bc_offset: bc_offset as u32,
                    bc_len: bc.len() as u32,
                });
            }

            // 选择入口 region：优先匹配 ELF 真实 entry point，否则 _start / main，否则 0。
            let entry_region = regions
                .iter()
                .position(|r| r.patch_addr == obj.entry)
                .or_else(|| {
                    let entry_names = ["_start", "main"];
                    funcs.iter().position(|f| entry_names.iter().any(|&e| f.name == e))
                })
                .unwrap_or(0) as u32;
            log::info!(
                "entry region = {} ({})",
                entry_region,
                funcs.get(entry_region as usize).map(|f| f.name.as_str()).unwrap_or("?")
            );

            // 抽取原 ELF 的可加载非代码段（.rodata / .data / .bss），blob 启动时映射到原 vaddr。
            // 这样被 lift 的代码里 ADR / LDR-literal / 全局变量访问在 vmp-runtime 进程里也有效。
            let mut data_segments: Vec<vmp_stub::DataSegment> = Vec::new();
            extract_data_segments(&obj.raw, &mut data_segments);
            log::info!(
                "data segments: {} 段，共 {} 字节",
                data_segments.len(),
                data_segments.iter().map(|d| d.bytes.len()).sum::<usize>()
            );

            let blob = StubBlob {
                spec,
                regions,
                bytecode_pool: pool,
                entry_region,
                data_segments,
            };
            let packed = pack_blob(&blob);
            fs::write(&output, &packed)?;
            log::info!(
                "保护完成：{} regions / 字节码池 {} 字节 / blob {} 字节 → {}",
                blob.regions.len(),
                blob.bytecode_pool.len(),
                packed.len(),
                output.display()
            );
        }

        Cmd::Lift { file, hex: hexstr, base, arch } => {
            let bytes = if let Some(p) = file {
                fs::read(p)?
            } else if let Some(s) = hexstr {
                let s: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
                hex::decode(&s).context("hex 解码失败")?
            } else {
                anyhow::bail!("必须指定 --file 或 --hex");
            };
            let arch = match arch {
                ArchArg::Arm64 => vmp_core::Arch::Arm64,
                ArchArg::X86_64 => vmp_core::Arch::X86_64,
            };
            let lifted = vmp_arch::lift(arch, &bytes, base)?;
            println!(
                "lifted {} IR ({} 输入 / 跳过 {})",
                lifted.ir.len(),
                lifted.report.total_input,
                lifted.report.skipped
            );
            for (i, ins) in lifted.ir.iter().enumerate() {
                println!("  [{:04}] {:?}", i, ins);
            }
            for n in &lifted.report.notes {
                println!("  note: {n}");
            }
        }

        Cmd::Run { blob, region, arg } => {
            let raw = fs::read(&blob)?;
            let blob = unpack_blob(&raw)?;
            let mut host = vmp_stub::entry::NullHost;
            let r = vmp_stub::dispatch_vm(&blob, region, &arg, &mut host)?;
            println!("region {} 返回值 = {} (0x{:x})", region, r, r);
        }

        Cmd::Rewrite { input, blob, output, write_trampolines, strip_names, xor_payload, encrypt_rodata, log, embed_runtime } => {
            let elf_bytes = fs::read(&input)?;
            let loaded = vmp_loader::load(elf_bytes)?;
            let blob_bytes = fs::read(&blob)?;
            let stub_blob = vmp_stub::unpack_blob(&blob_bytes)?;
            let embed_so_bytes = if let Some(p) = &embed_runtime {
                Some(fs::read(p).with_context(|| format!("read {}", p.display()))?)
            } else {
                None
            };
            let opts = vmp_rewriter::RewriteOptions {
                write_entry_trampolines: write_trampolines,
                embed_runtime_so: embed_so_bytes,
            };
            let (mut new_elf, report) = vmp_rewriter::rewrite_elf(&loaded, &stub_blob, &opts)
                .map_err(|e| anyhow::anyhow!("rewrite failed: {e}"))?;

            let log_on = matches!(log.as_str(), "on" | "1" | "true" | "yes");
            let armor_opts = vmp_rewriter::ArmorOptions {
                strip_shstrtab: strip_names,
                strip_symtab: strip_names,
                xor_payload,
                hash_imports: false,
                encrypt_rodata,
                log_on,
            };
            let armor_rep = vmp_rewriter::apply_armor(&mut new_elf, report.blob_offset, &armor_opts)
                .map_err(|e| anyhow::anyhow!("armor failed: {e}"))?;

            fs::write(&output, &new_elf)?;
            println!(
                "rewrite ok: kind={:?} patched_entries={} new_segment_vaddr={:#x} \
                 new_segment_size={} blob_offset={:#x}\n\
                 armor: shstrtab_zeroed={} strtab_zeroed={} payload_xor_len={} \
                 rodata_vaddr={:#x} rodata_enc_len={} imports_hashed={} log_on={}\n\
                 embed: bootstrap_vaddr={:#x} embedded_so_vaddr={:#x} embedded_so_len={} init_array_vaddr={:#x}\n\
                 → {} ({} bytes)",
                loaded.kind,
                report.patched_entries,
                report.new_segment_vaddr,
                report.new_segment_size,
                report.blob_offset,
                armor_rep.shstrtab_zeroed,
                armor_rep.strtab_zeroed,
                armor_rep.payload_xor_len,
                armor_rep.rodata_vaddr,
                armor_rep.rodata_encrypted_len,
                armor_rep.imports_hashed,
                log_on,
                report.bootstrap_vaddr,
                report.embedded_so_vaddr,
                report.embedded_so_len,
                report.init_array_vaddr,
                output.display(),
                new_elf.len()
            );
        }

        Cmd::ArList { archive } => {
            let bytes = fs::read(&archive)?;
            let mems = vmp_loader::ar::members(&bytes)
                .map_err(|e| anyhow::anyhow!("解析 ar 失败: {e}"))?;
            println!("AR 成员 ({} 个):", mems.len());
            for m in &mems {
                println!("  {} @ {:#x} size={}", m.name, m.offset, m.size);
            }
        }

        Cmd::Inspect { blob } => {
            let raw = fs::read(&blob)?;
            let b = unpack_blob(&raw)?;
            println!("magic = QVMP v1");
            println!("ISA fingerprint = {}", hex::encode(b.spec.fingerprint));
            println!("encrypt = {}", b.spec.encrypt);
            println!("opcode 总数 = {}", b.spec.op_table.len());
            println!("regions = {}", b.regions.len());
            for (i, r) in b.regions.iter().enumerate() {
                println!(
                    "  [{}] patch={:#x} len={} bc_off={} bc_len={}",
                    i, r.patch_addr, r.patch_len, r.bc_offset, r.bc_len
                );
            }
            println!("bytecode_pool = {} 字节", b.bytecode_pool.len());
        }
    }

    Ok(())
}
