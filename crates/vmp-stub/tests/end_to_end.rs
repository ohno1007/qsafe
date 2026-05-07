//! 端到端：lift → encode → pack → unpack → 解释执行。
//!
//! 这些测试不依赖目标二进制，只用裸字节码片段，避免外部依赖。

use vmp_codegen::{resolve_program, CodeGen, FunctionRegion};
use vmp_core::Arch;
use vmp_interpreter::HostBridge;
use vmp_isa::{Instr, IsaRandomizer, Width};
use vmp_stub::entry::NullHost;
use vmp_stub::{dispatch_vm, pack_blob, unpack_blob, StubBlob, StubRegion};

/// 完整 fpdemo 端到端跑（仅 Linux/Android 可用：依赖 mmap MAP_FIXED 映射原 vaddr .rodata；
/// Windows 进程地址布局不允许低地址 0x200190 区映射，本地标 ignore，仅在 device adb 测）。
#[test]
#[ignore = "需要 mmap MAP_FIXED；仅设备验证"]
fn arm64_fpdemo_full_path() {
    let elf_bytes = std::fs::read("../../samples/fpdemo/fpdemo").unwrap();
    let obj = vmp_loader::load(elf_bytes).unwrap();

    let mut funcs: Vec<FunctionRegion> = Vec::new();
    for sym in &obj.symbols {
        let region = match obj.code.iter().find(|r| r.contains(sym.vaddr)) {
            Some(r) => r,
            None => continue,
        };
        let off = (sym.vaddr - region.vaddr) as usize;
        let end = off + sym.size as usize;
        if end > region.bytes.len() {
            continue;
        }
        let bytes = &region.bytes[off..end];
        let lifted = vmp_arch::lift(obj.arch, bytes, sym.vaddr).unwrap();
        funcs.push(FunctionRegion {
            name: sym.name.clone(),
            vaddr: sym.vaddr,
            size: sym.size,
            ir: lifted.ir,
            native_to_ir: lifted.native_to_ir,
        });
    }
    resolve_program(&mut funcs);

    let cfg_seed: u64 = 0xDEADBEEF;
    let spec = IsaRandomizer::new(cfg_seed, 2, true).build();
    let mut pool = Vec::new();
    let mut regions = Vec::new();
    for (idx, f) in funcs.iter().enumerate() {
        let mut cg = CodeGen::new(&spec, cfg_seed.wrapping_add(f.vaddr), 25, 2)
            .with_iv_salt(idx as u64);
        let bc = cg.encode(&f.ir).unwrap();
        regions.push(StubRegion {
            patch_addr: f.vaddr,
            patch_len: f.size as u32,
            bc_offset: pool.len() as u32,
            bc_len: bc.len() as u32,
        });
        pool.extend_from_slice(&bc);
    }
    let entry = funcs.iter().position(|f| f.name == "_start").unwrap();

    // 抽取原 ELF 的 .rodata / .data 段（fpdemo 用 .rodata 存初始化数组）
    let mut data_segments = Vec::new();
    extract_data_segs(&obj.raw, &mut data_segments);

    let blob = StubBlob {
        spec,
        regions,
        bytecode_pool: pool,
        entry_region: entry as u32,
        data_segments,
    };

    let mut th = TraceHost { writes: vec![], exit_code: None, load_count: 0, store_count: 0 };
    let r = dispatch_vm(&blob, entry, &[1, 0, 0, 0, 0, 0, 0, 0], &mut th);
    println!("dispatch_vm result={:?}", r);
    println!("exit_code={:?}", th.exit_code);
    assert_eq!(th.exit_code, Some(40), "fpdemo 应当 exit(40)，实际 {:?}", th.exit_code);
}

/// 验证 FP scalar 路径：scale(60.0, 2.0, 3.0) 应该返回 40.0
#[test]
fn arm64_fpdemo_scale_returns_40() {
    let elf_bytes = std::fs::read("../../samples/fpdemo/fpdemo").unwrap();
    let obj = vmp_loader::load(elf_bytes).unwrap();
    let scale_sym = obj.symbols.iter().find(|s| s.name == "scale").unwrap();
    let region = obj.code.iter().find(|r| r.contains(scale_sym.vaddr)).unwrap();
    let off = (scale_sym.vaddr - region.vaddr) as usize;
    let bytes = &region.bytes[off..off + scale_sym.size as usize];

    let lifted = vmp_arch::lift(obj.arch, bytes, scale_sym.vaddr).unwrap();
    assert_eq!(lifted.report.skipped, 0, "scale 应当 0 跳过: {:?}", lifted.report.notes);
    let mut funcs = vec![FunctionRegion {
        name: "scale".into(),
        vaddr: scale_sym.vaddr,
        size: scale_sym.size,
        ir: lifted.ir,
        native_to_ir: lifted.native_to_ir,
    }];
    resolve_program(&mut funcs);

    let spec = IsaRandomizer::new(7, 2, true).build();
    let mut cg = CodeGen::new(&spec, 11, 0, 2);
    let bc = cg.encode(&funcs[0].ir).unwrap();

    let blob = StubBlob {
        spec,
        regions: vec![StubRegion {
            patch_addr: scale_sym.vaddr,
            patch_len: scale_sym.size as u32,
            bc_offset: 0,
            bc_len: bc.len() as u32,
        }],
        bytecode_pool: bc,
        entry_region: 0,
        data_segments: vec![],
    };

    // scale(d0=60.0, d1=2.0, d2=3.0) → d0 = 40.0
    // 调用约定：FP 参数在 D0/D1/D2，返回值在 D0
    let mut host = NullHost;
    // 通过 vm_call_region 方式（让我们直接用 dispatch_vm；但该 API 不支持 FP 入参）
    // 解决方案：手工创建一个 Interpreter，自己塞 fregs 再跑 run。
    use vmp_interpreter::Interpreter;
    let bc_decrypt_view = &blob.bytecode_pool[..];
    let mut interp = Interpreter::new(&blob.spec, bc_decrypt_view).with_host(&mut host).with_iv_salt(0);
    // 给 SP 一块栈（避免任何潜在 prologue 操作；scale 其实是 leaf）
    let mut vm_stack: Vec<u64> = vec![0u64; 8192];
    let stack_top = (vm_stack.as_mut_ptr() as u64).wrapping_add(64 * 1024);
    interp.state.regs[31] = stack_top & !0xFu64;
    interp.state.fregs[0] = 60.0f64.to_bits() as u128;
    interp.state.fregs[1] = 2.0f64.to_bits() as u128;
    interp.state.fregs[2] = 3.0f64.to_bits() as u128;
    let _ = interp.run().unwrap();
    let result = f64::from_bits(interp.state.fregs[0] as u64);
    println!("scale(60, 2, 3) = {}", result);
    assert!((result - 40.0).abs() < 1e-9, "scale 期望 40.0, 实际 {}", result);
}

/// 模拟整条 multifn 的 protect 流程，验证 sum_of_squares region 用 iv_salt=2 加密后能正确返回 385。
#[test]
fn arm64_multifn_full_protect_path() {
    let elf_bytes = std::fs::read("../../samples/multifn/multifn").unwrap();
    let obj = vmp_loader::load(elf_bytes).unwrap();

    let mut funcs: Vec<FunctionRegion> = Vec::new();
    for sym in &obj.symbols {
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
        let lifted = vmp_arch::lift(obj.arch, func_bytes, sym.vaddr).unwrap();
        funcs.push(FunctionRegion {
            name: sym.name.clone(),
            vaddr: sym.vaddr,
            size: sym.size,
            ir: lifted.ir,
            native_to_ir: lifted.native_to_ir,
        });
    }
    resolve_program(&mut funcs);

    let cfg_seed: u64 = 0xDEADBEEF;
    let spec = IsaRandomizer::new(cfg_seed, 2, true).build();
    let mut pool = Vec::new();
    let mut regions = Vec::new();
    for (region_idx, func) in funcs.iter().enumerate() {
        let mut cg = CodeGen::new(&spec, cfg_seed.wrapping_add(func.vaddr), 25, 2)
            .with_iv_salt(region_idx as u64);
        let bc = cg.encode(&func.ir).unwrap();
        regions.push(StubRegion {
            patch_addr: func.vaddr,
            patch_len: func.size as u32,
            bc_offset: pool.len() as u32,
            bc_len: bc.len() as u32,
        });
        pool.extend_from_slice(&bc);
    }

    let blob = StubBlob {
        spec,
        regions,
        bytecode_pool: pool,
        entry_region: 0,
        data_segments: vec![],
    };

    // 找 sum_of_squares region id
    let sumsq_idx = funcs.iter().position(|f| f.name == "sum_of_squares").unwrap();
    println!("sum_of_squares 在 region {}", sumsq_idx);

    let mut host = NullHost;
    let r = dispatch_vm(&blob, sumsq_idx, &[10, 0, 0, 0, 0, 0, 0, 0], &mut host).unwrap();
    println!("dispatch_vm sum_of_squares(10) = {}", r);
    assert_eq!(r, 385, "完整 protect 路径 sum_of_squares(10) 应 = 385，实际 {}", r);

    // 现在模拟 device 链路：从 _start 进入，args[1] = 一个 ptr（如 device 实际跑那样）
    let start_idx = funcs.iter().position(|f| f.name == "_start").unwrap();
    println!("_start 在 region {}", start_idx);

    let mut th = TraceHost { writes: vec![], exit_code: None, load_count: 0, store_count: 0 };
    let _ = dispatch_vm(&blob, start_idx, &[1, 0xb40000_77800000_u64 as u64, 0, 0, 0, 0, 0, 0], &mut th);
    println!("via _start: writes={:?} exit={:?}", host_writes_strs(&th), th.exit_code);
    assert_eq!(th.exit_code, Some(385), "via _start exit 应该 385，实际 {:?}", th.exit_code);
    assert!(
        th.writes.iter().any(|w| w == b"385\n"),
        "via _start 应该 write 385\\n，实际 {:?}",
        host_writes_strs(&th)
    );
}

fn extract_data_segs(elf_bytes: &[u8], out: &mut Vec<vmp_stub::DataSegment>) {
    use goblin::elf::program_header::{PF_W, PF_X, PT_LOAD};
    use goblin::elf::Elf;
    let elf = match Elf::parse(elf_bytes) { Ok(e) => e, Err(_) => return };
    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD || (ph.p_flags & PF_X) != 0 { continue; }
        let off = ph.p_offset as usize;
        let fz = ph.p_filesz as usize;
        let mz = ph.p_memsz as usize;
        if off + fz > elf_bytes.len() { continue; }
        let mut bytes = elf_bytes[off..off+fz].to_vec();
        if mz > fz { bytes.resize(mz, 0); }
        let prot = 1u8 | if (ph.p_flags & PF_W) != 0 { 2 } else { 0 };
        out.push(vmp_stub::DataSegment { vaddr: ph.p_vaddr, bytes, prot });
    }
}

fn host_writes_strs(h: &TraceHost) -> Vec<String> {
    h.writes.iter().map(|w| String::from_utf8_lossy(w).to_string()).collect()
}

/// 单独跑 multifn 里的 sum_of_squares(10) 看 VM 是否返回 385。
#[test]
fn arm64_multifn_sum_of_squares() {
    // multifn 的 sum_of_squares 在 .text 偏移 0..68（17 instructions）
    let elf_bytes = std::fs::read("../../samples/multifn/multifn").unwrap();
    // 先找 .text 在 ELF 中的 file offset。简单解析 program header 的 PT_LOAD 找 X 段。
    // 直接 hardcode 0x274 没保证；改用 goblin 解析。
    let obj = vmp_loader::load(elf_bytes).unwrap();
    let region = obj.code.iter().find(|r| r.contains(0x204234)).unwrap();
    let off = (0x204234 - region.vaddr) as usize;
    let bytes = &region.bytes[off..off + 68];

    let ir = lift_one(bytes, 0x204234);
    println!("sum_of_squares lifted to {} IR", ir.len());

    let spec = IsaRandomizer::new(42, 2, true).build();
    let mut cg = CodeGen::new(&spec, 99, 0, 2);
    let bc = cg.encode(&ir).unwrap();

    let blob = StubBlob {
        spec,
        regions: vec![StubRegion {
            patch_addr: 0x204234,
            patch_len: 68,
            bc_offset: 0,
            bc_len: bc.len() as u32,
        }],
        bytecode_pool: bc,
        entry_region: 0,
        data_segments: vec![],
    };
    let mut host = NullHost;
    let r = dispatch_vm(&blob, 0, &[10, 0, 0, 0, 0, 0, 0, 0], &mut host).unwrap();
    println!("sum_of_squares(10) = {}", r);
    assert_eq!(r, 385, "sum_of_squares(10) 应该 = 385，VM 实际 {}", r);
}

/// 测试用：lift 一段裸 ARM64 字节 → resolve 单 region → 返回 (ir, native_to_ir)。
fn lift_one(bytes: &[u8], base: u64) -> Vec<Instr> {
    let lifted = vmp_arch::lift(Arch::Arm64, bytes, base).unwrap();
    let mut funcs = vec![FunctionRegion {
        name: "test".into(),
        vaddr: base,
        size: bytes.len() as u64,
        ir: lifted.ir,
        native_to_ir: lifted.native_to_ir,
    }];
    resolve_program(&mut funcs);
    funcs.pop().unwrap().ir
}

/// 构造一个 ARM64 序列：mov w0, #42 ; ret
/// 在 VM 下应当返回 42。
#[test]
fn arm64_mov_imm_ret_returns_42() {
    let bytes = hex_decode("40058052c0035fd6");
    let ir = lift_one(&bytes, 0x1000);
    assert!(!ir.is_empty());

    for encrypt in [false, true] {
        let spec = IsaRandomizer::new(0xCAFE_BABE, 2, encrypt).build();
        let mut cg = CodeGen::new(&spec, 0x1234, 0, 2);
        let bc = cg.encode(&ir).unwrap();

        let blob = StubBlob {
            spec,
            regions: vec![StubRegion {
                patch_addr: 0x1000,
                patch_len: bytes.len() as u32,
                bc_offset: 0,
                bc_len: bc.len() as u32,
            }],
            bytecode_pool: bc,
            entry_region: 0,
            data_segments: vec![],
        };

        let packed = pack_blob(&blob);
        let blob = unpack_blob(&packed).unwrap();
        let mut host = NullHost;
        let r = dispatch_vm(&blob, 0, &[], &mut host).unwrap();
        assert_eq!(r, 42, "encrypt={encrypt}");
    }
}

/// 构造一个加法序列：add x0, x0, x1 ; ret
/// 输入 v0=10, v1=32 → 期望 42
#[test]
fn arm64_add_xn_xm_returns_sum() {
    // ADD x0, x0, x1 = 0x8b010000
    // RET = 0xd65f03c0
    let bytes = hex_decode("0000018bc0035fd6");
    let r = run_arm64(&bytes, 0x2000, &[10, 32, 0, 0, 0, 0, 0, 0], 7, true);
    assert_eq!(r, 42);
}

/// factorial(W0)：循环、cmp、b.cond、mul、b 全部触发。期望 fact(5) = 120
#[test]
fn arm64_factorial_loop() {
    // 见 arm64.s 的注释；由 ARMv8 指令手册手写汇编。
    let prog = concat!(
        "21008052",  // mov w1, #1
        "22008052",  // mov w2, #1
        "5F00006B",  // cmp w2, w0
        "8C000054",  // b.gt done (+4 instructions = +16 字节)
        "217C021B",  // mul w1, w1, w2
        "42040011",  // add w2, w2, #1
        "FCFFFF17",  // b loop (-4 instructions)
        "E003012A",  // mov w0, w1
        "C0035FD6",  // ret
    );
    let bytes = hex_decode(prog);
    let r = run_arm64(&bytes, 0x4000, &[5, 0, 0, 0, 0, 0, 0, 0], 0xBEEF, true);
    assert_eq!(r, 120, "factorial(5) 应为 120, 实际 {}", r);
}

/// CBZ/CBNZ 测试：abs(x0) — 输入 -7 期望 7
#[test]
fn arm64_cbz_negate_when_negative() {
    // tbz w0, #31, .Lpos        ; 如果符号位为 0 跳过取反
    // neg w0, w0 (实际：sub w0, wzr, w0)
    // .Lpos:
    // ret
    // tbz w0,#31,+8: bits 5:bit_index=31. encoding: b5=1 011011 op=0 b40=11111 imm14=2 (=8/4) Rt=0
    // = 1_011011_0_11111_00000000000010_00000
    // = 0x37F80040
    // wait let me recompute. Check format: b5(1)|011011|op(1)|b40(5)|imm14(14)|Rt(5)
    // For w0: sf=0 ⇒ this is W reg, but bit b5 is 0 (since reg is 32-bit, bits 32-63 don't exist; bit_pos 31 needs b5=0 b40=11111).
    // Reading manual again: bit5 = imm[5], b40 = imm[4:0]. So bit_index 31 → b5=0 b40=11111
    // top_bit_field encoding: bit 31 = b5, bits 30:25 = 011011, bit 24 = op, bits 23:19 = b40, bits 18:5 = imm14, bits 4:0 = Rt
    // = 0_011011_0_11111_(imm14=2)_00000
    // = 0|0110110|11111|00000000000010|00000
    // bits 31|30..24|23..19|18..5|4..0
    // value: 36F80040
    // Let me compute: (0x36 << 24) | (0x1F << 19) | (2 << 5) | 0
    //   0x36 << 24 = 0x36000000
    //   wait my bit packing - 30:25 = 011011 = 0x1B, op at 24 = 0
    //   So bits 31:24 = 0_0110110 = 0x36
    //   bits 23:19 = 11111 = 0x1F → (0x1F << 19) = 0x00F80000
    //   imm14 = 2 → bits 18:5 = 0x02 → (2 << 5) = 0x40
    //   Rt = 0
    //   Total = 0x36F80040
    // SUB w0, wzr, w0 = NEG alias: sf|10|01011|shift|0|Rm|imm6|Rn|Rd
    //   = 0|10|01011|00|0|00000|000000|11111|00000 → 0|10|01011|00|0|0_00000|000000|11111|00000
    //   bits 31|30:29|28:24|23:22|21|20:16|15:10|9:5|4:0
    //   = 0_10_01011_00_0_00000_000000_11111_00000
    //   = 0100_1011_0000_0000_0000_0011_1110_0000
    //   = 0x4B0003E0
    // RET = 0xD65F03C0
    let prog = concat!(
        "40 00 F8 36",  // tbz w0, #31, .Lpos (+8)
        "E0 03 00 4B",  // sub w0, wzr, w0 (= neg w0, w0)
        "C0 03 5F D6",  // ret
    );
    let prog = prog.replace(' ', "");
    let bytes = hex_decode(&prog);

    // 输入 7：跳过 neg，返回 7
    let r = run_arm64(&bytes, 0x5000, &[7, 0, 0, 0, 0, 0, 0, 0], 1, false);
    assert_eq!(r, 7);

    // 输入 -7（u32 视角 = 0xFFFFFFF9 ≈ 4294967289）：执行 neg → 7
    // 但我们的 lifter 把 SUB(reg) 解码成宽度 W32，结果为 7 在低 32 位。
    let neg7_w32: u64 = ((-7i32) as u32) as u64;
    let r = run_arm64(&bytes, 0x5000, &[neg7_w32, 0, 0, 0, 0, 0, 0, 0], 2, false);
    assert_eq!(r & 0xFFFF_FFFF, 7);
}

/// 同时验证 ADRP+ADD（PIC pattern）：取 PC 相对常量地址。
#[test]
fn arm64_adrp_emits_absolute_address() {
    // adrp x0, #0  → 取当前页对齐基址
    // ret
    // ADRP encoding: 1|immlo|10000|immhi|Rd=0
    // imm=0 → 0|10000|0|0 → bits: 1_00_10000_0000000000000000000_00000 = 0x90000000
    let bytes = hex_decode("00000090c0035fd6");
    let r = run_arm64(&bytes, 0x4000, &[0; 8], 33, false);
    // PC 为函数入口；ADRP 的结果是 PC & ~0xFFF = 0x4000
    assert_eq!(r, 0x4000);
}

/// 真实 NDK 编译出来的 sumsq.text（_start 144 字节，36 条指令）。
/// 拦截 syscall：write 把内容写入 captured_writes；exit 立刻把 VM 停下来。
#[test]
fn arm64_real_sumsq_returns_385() {
    let path = "../../samples/sumsq/sumsq.text";
    let bytes = std::fs::read(path).expect("需要先 cross-compile sumsq");
    assert_eq!(bytes.len(), 144);

    let lifted = vmp_arch::lift(Arch::Arm64, &bytes, 0x20419c).unwrap();
    assert_eq!(
        lifted.report.skipped, 0,
        "lifter 还有未支持指令: {:?}",
        lifted.report.notes
    );
    let mut funcs = vec![FunctionRegion {
        name: "_start".into(),
        vaddr: 0x20419c,
        size: bytes.len() as u64,
        ir: lifted.ir,
        native_to_ir: lifted.native_to_ir,
    }];
    resolve_program(&mut funcs);
    let ir = funcs.pop().unwrap().ir;

    let spec = IsaRandomizer::new(0x12345678, 2, true).build();
    let mut cg = CodeGen::new(&spec, 0xABCDEF, 0, 2);
    let bc = cg.encode(&ir).unwrap();

    let blob = StubBlob {
        spec,
        regions: vec![StubRegion {
            patch_addr: 0x20419c,
            patch_len: bytes.len() as u32,
            bc_offset: 0,
            bc_len: bc.len() as u32,
        }],
        bytecode_pool: bc,
        entry_region: 0,
        data_segments: vec![],
    };

    let mut host = TraceHost {
        writes: Vec::new(),
        exit_code: None,
        load_count: 0,
        store_count: 0,
    };

    let r = dispatch_vm(&blob, 0, &[0u64; 8], &mut host);
    // 我们用 Err("__VM_EXIT__") 让 host 强制跳出 VM 循环；任何返回都接受。
    let _ = r;

    println!(
        "load_count={} store_count={} writes={} exit_code={:?}",
        host.load_count, host.store_count, host.writes.len(), host.exit_code
    );
    for (i, w) in host.writes.iter().enumerate() {
        println!("  write[{}]: {:?}", i, std::str::from_utf8(w));
    }

    assert_eq!(host.exit_code, Some(385), "VM 应该 exit(385)，实际 {:?}", host.exit_code);
    assert!(
        host.writes.iter().any(|w| w == b"385\n"),
        "VM 应该 write \"385\\n\"，实际 {:?}",
        host.writes.iter().map(|w| String::from_utf8_lossy(w).to_string()).collect::<Vec<_>>()
    );
}

/// 模拟 `vmp protect` 流程：lift sumsq.text → spec(seed=DEADBEEF, dup=2) → codegen(seed+addr, junk=25)。
/// 和 cli 用的种子 / junk 设置完全一致，验证 cli 路径下产出的 blob 是否可执行。
#[test]
fn arm64_simulate_cli_protect_path() {
    use vmp_codegen::CodeGen;
    let bytes = std::fs::read("../../samples/sumsq/sumsq.text").unwrap();
    let ir = lift_one(&bytes, 0x20419c);

    // 与 ProtectLevel::Standard 完全一致的参数
    let cfg_seed: u64 = 0xDEADBEEF;
    let dup: u8 = 2;
    let encrypt = true;
    let junk_density: u8 = 25;

    let spec = IsaRandomizer::new(cfg_seed, dup, encrypt).build();
    let mut cg = CodeGen::new(&spec, cfg_seed.wrapping_add(0x20419c), junk_density, dup);
    let bc = cg.encode(&ir).unwrap();

    // 解密一份本地副本看原始字节是否合法
    let mut decrypted = bc.clone();
    if encrypt {
        vmp_codegen::stream::decrypt_in_place(&mut decrypted, &spec.stream_key, &spec.stream_iv);
    }
    println!("encrypted bc[0..40]:  {:02x?}", &bc[..40.min(bc.len())]);
    println!("decrypted bc[0..40]:  {:02x?}", &decrypted[..40.min(decrypted.len())]);

    // 对每个 byte 在 op_reverse 表里查询，找出第一个未识别的 byte 位置
    for (i, b) in decrypted.iter().enumerate() {
        if spec.op_reverse[*b as usize].is_none() {
            // 这个 byte 可能是合法的 operand（reg/imm 字节），不一定是 opcode 位置
            // 但若 step-by-step 解码到这里仍报"未知 opcode"则说明它确实在 opcode 槽位
            if i < 20 {
                println!("  decrypted[{}]=0x{:02x} 不在 op_reverse 表中（可能是 operand 或非法）", i, b);
            }
        }
    }

    // step-by-step 解码看走到哪里失败
    let mut pos = 0;
    let mut step = 0;
    while pos < decrypted.len() {
        match vmp_isa::decode_instr(&spec, &decrypted[pos..]) {
            Ok((instr, len)) => {
                if step < 3 || step > 38 {
                    println!("step {} pos=0x{:x} {:?} rd={} rs={} rt={} imm={} len={}",
                        step, pos, instr.op, instr.rd, instr.rs, instr.rt, instr.imm, len);
                }
                pos += len;
                step += 1;
            }
            Err(e) => {
                println!("STEP {} pos=0x{:x} byte=0x{:02x} ERR {}", step, pos, decrypted[pos], e);
                break;
            }
        }
    }

    let mut blob = StubBlob {
        spec,
        regions: vec![StubRegion {
            patch_addr: 0x20419c,
            patch_len: bytes.len() as u32,
            bc_offset: 0,
            bc_len: bc.len() as u32,
        }],
        bytecode_pool: bc,
        entry_region: 0,
        data_segments: vec![],
    };

    // 路径 A: 直接 dispatch
    let mut h = TraceHost { writes: vec![], exit_code: None, load_count: 0, store_count: 0 };
    let r_direct = dispatch_vm(&blob, 0, &[0u64; 8], &mut h);
    println!("DIRECT: result={:?} exit={:?}", r_direct, h.exit_code);

    // 路径 B: pack → unpack → dispatch
    let packed = pack_blob(&blob);
    let blob_b = unpack_blob(&packed).unwrap();
    blob = blob_b;
    let mut h = TraceHost { writes: vec![], exit_code: None, load_count: 0, store_count: 0 };
    let r_packed = dispatch_vm(&blob, 0, &[0u64; 8], &mut h);
    println!("PACKED: result={:?} exit={:?}", r_packed, h.exit_code);
}

#[test]
fn isaspec_pack_unpack_roundtrip() {
    let spec1 = IsaRandomizer::new(0xDEADBEEF_u64.wrapping_add(0x20419c), 2, true).build();
    // 直接 pack / unpack ISA spec（通过 StubBlob 间接）
    let blob1 = StubBlob {
        spec: spec1.clone(),
        regions: vec![],
        bytecode_pool: vec![],
        entry_region: 0,
        data_segments: vec![],
    };
    let packed = pack_blob(&blob1);
    let blob2 = unpack_blob(&packed).expect("unpack");
    let spec2 = &blob2.spec;

    let mut diffs = Vec::new();
    if spec1.fingerprint != spec2.fingerprint { diffs.push(format!("fingerprint mismatch")); }
    if spec1.reg_perm != spec2.reg_perm { diffs.push(format!("reg_perm mismatch")); }
    if spec1.reg_unperm != spec2.reg_unperm { diffs.push(format!("reg_unperm mismatch")); }
    if spec1.stream_key != spec2.stream_key { diffs.push(format!("stream_key mismatch")); }
    if spec1.stream_iv != spec2.stream_iv { diffs.push(format!("stream_iv mismatch")); }
    if spec1.imm_rol != spec2.imm_rol { diffs.push(format!("imm_rol mismatch")); }
    if spec1.branch_xor != spec2.branch_xor { diffs.push(format!("branch_xor mismatch")); }
    if spec1.encrypt != spec2.encrypt { diffs.push(format!("encrypt mismatch")); }
    for i in 0..256 {
        if spec1.op_reverse[i] != spec2.op_reverse[i] {
            diffs.push(format!("op_reverse[{:#x}] before={:?} after={:?}", i, spec1.op_reverse[i], spec2.op_reverse[i]));
        }
    }
    println!("op_table.len: before={} after={}", spec1.op_table.len(), spec2.op_table.len());
    for (k, v) in &spec1.op_table {
        if !spec2.op_table.contains_key(k) {
            diffs.push(format!("op_table missing key {}", k));
        }
    }
    if !diffs.is_empty() {
        for d in &diffs {
            println!("  DIFF: {}", d);
        }
        panic!("{} differences detected", diffs.len());
    }
    println!("OK roundtrip 完美一致");
}

/// 读 .qvmp 文件 → unpack_blob → dispatch_vm。复现 packed-blob 路径下的 bug。
#[test]
fn arm64_real_sumsq_via_packed_blob() {
    let bytes = std::fs::read("../../samples/sumsq/sumsq.qvmp").expect("缺少 sumsq.qvmp");
    let blob = unpack_blob(&bytes).expect("unpack");
    println!(
        "blob: regions={} pool={} encrypt={} opcodes={}",
        blob.regions.len(),
        blob.bytecode_pool.len(),
        blob.spec.encrypt,
        blob.spec.op_table.len()
    );

    let mut host = TraceHost {
        writes: Vec::new(),
        exit_code: None,
        load_count: 0,
        store_count: 0,
    };
    let r = dispatch_vm(&blob, 0, &[0u64; 8], &mut host);
    println!(
        "dispatch_vm result={:?} writes={} exit_code={:?}",
        r, host.writes.len(), host.exit_code
    );
    for w in &host.writes {
        println!("  write: {:?}", String::from_utf8_lossy(w));
    }
}

struct TraceHost {
    writes: Vec<Vec<u8>>,
    exit_code: Option<u64>,
    load_count: usize,
    store_count: usize,
}

impl HostBridge for TraceHost {
    fn load(&mut self, addr: u64, w: Width) -> vmp_core::Result<u64> {
        self.load_count += 1;
        unsafe {
            let v = match w {
                Width::W8 => *(addr as *const u8) as u64,
                Width::W16 => *(addr as *const u16) as u64,
                Width::W32 => *(addr as *const u32) as u64,
                Width::W64 => *(addr as *const u64),
            };
            Ok(v)
        }
    }
    fn store(&mut self, addr: u64, value: u64, w: Width) -> vmp_core::Result<()> {
        self.store_count += 1;
        unsafe {
            match w {
                Width::W8 => *(addr as *mut u8) = value as u8,
                Width::W16 => *(addr as *mut u16) = value as u16,
                Width::W32 => *(addr as *mut u32) = value as u32,
                Width::W64 => *(addr as *mut u64) = value,
            }
        }
        Ok(())
    }
    fn native_call(&mut self, _t: u64, _args: &[u64]) -> vmp_core::Result<u64> {
        Ok(0)
    }
    fn syscall(&mut self, no: u64, args: &[u64]) -> vmp_core::Result<u64> {
        // Linux/Android aarch64: 64=write(fd,buf,len) 93=exit(code)
        match no {
            64 => {
                let buf_ptr = args[1] as *const u8;
                let len = args[2] as usize;
                let slice = unsafe { std::slice::from_raw_parts(buf_ptr, len) };
                self.writes.push(slice.to_vec());
                Ok(len as u64)
            }
            93 => {
                self.exit_code = Some(args[0]);
                // 让 VM 立即停止：返回 Err 让 dispatch_vm 上层捕获
                Err(vmp_core::Error::vm("__VM_EXIT__"))
            }
            _ => Ok(0),
        }
    }
}

fn run_arm64(bytes: &[u8], base: u64, args: &[u64; 8], seed: u64, encrypt: bool) -> u64 {
    let ir = lift_one(bytes, base);
    let spec = IsaRandomizer::new(seed, 2, encrypt).build();
    let mut cg = CodeGen::new(&spec, seed.wrapping_add(1), 0, 2);
    let bc = cg.encode(&ir).unwrap();
    let blob = StubBlob {
        spec,
        regions: vec![StubRegion {
            patch_addr: base,
            patch_len: bytes.len() as u32,
            bc_offset: 0,
            bc_len: bc.len() as u32,
        }],
        bytecode_pool: bc,
        entry_region: 0,
        data_segments: vec![],
    };
    let packed = pack_blob(&blob);
    let blob = unpack_blob(&packed).unwrap();
    let mut host = NullHost;
    dispatch_vm(&blob, 0, args, &mut host).unwrap()
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let h = (bytes[i] as char).to_digit(16).unwrap() as u8;
        let l = (bytes[i + 1] as char).to_digit(16).unwrap() as u8;
        out.push((h << 4) | l);
        i += 2;
    }
    out
}
