# TODO

完整路线图见 [docs/ROADMAP.md](docs/ROADMAP.md)。
历史 Phase 见 [CHANGELOG.md](CHANGELOG.md)。

## 进行中 / 即将做

- [ ] NDK 端到端真机验证（用户本地）
- [ ] Hybrid thunk 加 V0..V31 寄存器保存恢复
- [ ] `.eh_frame` unwind 表跳板感知
- [ ] BTI rewriter 自动启用（已有 `build_brk_trampoline_bti`，未默认接到 rewriter）

## 短期补完

- [ ] NEON LD1/ST1 多结构、TBL/TBX、FCMEQ/FCMGT 向量比较、CRC32
- [ ] ARMv7 Thumb T2 32-bit 子集
- [ ] Anti-frida 加 27043 端口 + lib 后缀模糊匹配
- [ ] Integrity hash 嵌入默认开

## 调研

- [ ] x86_64 接 `iced-x86`
- [ ] Mach-O 加固（macOS / iOS）
- [ ] 多线程 VmState 池（取代 DISPATCH_LOCK）

每项的工程量评估见 ROADMAP。
