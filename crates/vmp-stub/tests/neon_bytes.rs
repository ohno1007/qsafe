use vmp_arch::lift;
use vmp_codegen::CodeGen;
use vmp_core::Arch;
use vmp_interpreter::Interpreter;
use vmp_isa::{Instr, IsaRandomizer, VOp};
use vmp_stub::{pack_blob, unpack_blob, StubBlob, StubRegion};

type Registers = [u128; 32];
const RET: u32 = 0xd65f_03c0;

fn execute(word: u32, registers: Registers) -> Registers {
    let mut code = word.to_le_bytes().to_vec();
    code.extend_from_slice(&RET.to_le_bytes());
    let lifted = lift(Arch::Arm64, &code, 0x1000).unwrap();
    assert_eq!(lifted.report.skipped, 0, "word {word:08x}");
    let spec = IsaRandomizer::new(42, 4, true).build();
    let bytes = CodeGen::new(&spec, 23, 0, 4).encode(&lifted.ir).unwrap();
    let blob = StubBlob {
        spec,
        regions: vec![StubRegion {
            patch_addr: 0x1000, patch_len: 8, bc_offset: 0, bc_len: bytes.len() as u32,
        }],
        entry_region: 0,
        bytecode_pool: bytes,
        data_segments: vec![],
    };
    let blob = unpack_blob(&pack_blob(&blob)).unwrap();
    let mut vm = Interpreter::new(&blob.spec, &blob.bytecode_pool);
    vm.state.fregs = registers;
    vm.run().unwrap();
    vm.state.fregs
}

#[test]
fn ext_all_offsets_and_overlapping_destination() {
    let left: [u8; 16] = std::array::from_fn(|i| 0x10 + i as u8);
    let right: [u8; 16] = std::array::from_fn(|i| 0xa0 + i as u8);
    let mut initial = [0; 32];
    initial[2] = u128::from_le_bytes(left);
    initial[3] = u128::from_le_bytes(right);
    for (lanes, base) in [(8, 0x2e03_0043u32), (16, 0x6e03_0043)] {
        // ext v3, v2, v3, #offset
        let joined = [&left[..lanes], &right[..lanes]].concat();
        for offset in 0..lanes {
            let mut expected = initial;
            let mut result = [0; 16];
            result[..lanes].copy_from_slice(&joined[offset..offset + lanes]);
            expected[3] = u128::from_le_bytes(result);
            assert_eq!(execute(base | ((offset as u32) << 11), initial), expected);
        }
    }
}

#[test]
fn tables_all_lengths_bounds_and_register_wraparound() {
    let indices = [0, 15, 16, 31, 32, 47, 48, 63, 64, 255, 1, 14, 17, 30, 33, 62];
    let mut initial = [0; 32];
    for (table, reg) in [31, 0, 1, 2].into_iter().enumerate() {
        // Every table byte equals its index XOR 0x80, including across V31 -> V0.
        let bytes = std::array::from_fn(|i| (16 * table + i) as u8 ^ 0x80);
        initial[reg] = u128::from_le_bytes(bytes);
    }
    initial[6] = u128::from_le_bytes(indices);
    for (lanes, q) in [(8, 0u32), (16, 1 << 30)] {
        for count in 1..=4 {
            // TBL overwrites its first table register. TBX overwrites its index register.
            for (base, rd, keep) in [(0x0e06_03ffu32, 31, false), (0x0e06_13e6, 6, true)] {
                let word = base | q | ((count - 1) << 13);
                let mut result = [0; 16];
                for i in 0..lanes {
                    if u32::from(indices[i]) < count * 16 {
                        result[i] = indices[i] ^ 0x80;
                    } else if keep {
                        result[i] = indices[i];
                    }
                }
                let mut expected = initial;
                expected[rd] = u128::from_le_bytes(result);
                assert_eq!(execute(word, initial), expected, "word {word:08x}");
            }
        }
    }
}

#[test]
fn reserved_ext_offset_and_invalid_bytecode_operands_are_rejected() {
    // The 8B form reserves offsets 8..15.
    for offset in 8..16 {
        let word = 0x2e03_0043u32 | (offset << 11);
        let lifted = lift(Arch::Arm64, &word.to_le_bytes(), 0).unwrap();
        assert_eq!(lifted.report.skipped, 1);
        assert_eq!(lifted.ir[0].op, VOp::Trap);
    }
    let spec = IsaRandomizer::new(1, 1, false).build();
    for instr in [
        Instr::vector_bytes(VOp::VExt, 0, 1, 2, false, 8),
        Instr::vector_bytes(VOp::VTbl, 0, 1, 2, true, 0),
        Instr::vector_bytes(VOp::VTbx, 0, 1, 2, true, 5),
        Instr::vector_bytes(VOp::VTbl, 0, 32, 2, true, 1),
    ] {
        let ret = Instr { op: VOp::Ret, ..Instr::default() };
        let bytes = CodeGen::new(&spec, 1, 0, 1).encode(&[instr, ret]).unwrap();
        assert!(Interpreter::new(&spec, &bytes).run().is_err());
    }
}
