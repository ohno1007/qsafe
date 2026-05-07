// sumsq.S — 计算 1^2 + 2^2 + ... + N^2，以结果作为 exit code
//
// 这是 VMP 端到端演示用的最小 aarch64 Linux 程序：
//   - 全部逻辑在 _start 内（单 region，便于现阶段 vmp-runtime 直接以 region 0 进入）
//   - 用 SVC #0 / X8 = 93 (sys_exit) 触发 syscall，验证 lifter + 解释器对系统调用的支持
//   - N = 10  →  385  →  低 8 位作为 exit code = 0x81 = 129
//
// 交叉编译（aarch64-linux-gnu）:
//   aarch64-linux-gnu-gcc -nostdlib -static -o sumsq sumsq.S
//   ./sumsq ; echo $?     # 期望 129
//
// 加 VMP 保护:
//   ../../target/release/vmp protect ./sumsq -o ./sumsq.qvmp --level heavy
//   QVMP_BLOB=$(pwd)/sumsq.qvmp \
//     cargo build --release --target aarch64-unknown-linux-gnu -p vmp-runtime
//   ./target/aarch64-unknown-linux-gnu/release/vmp-runtime ; echo $?  # 同样 129

.global _start
.section .text

_start:
    mov     w0, #10           // N = 10
    mov     w1, #0            // sum = 0
    mov     w2, #1            // i = 1
.Lloop:
    cmp     w2, w0
    b.gt    .Ldone            // i > N → 退出循环
    mul     w3, w2, w2        // w3 = i*i
    add     w1, w1, w3        // sum += w3
    add     w2, w2, #1        // i++
    b       .Lloop
.Ldone:
    mov     x0, x1            // exit_code = sum
    mov     x8, #93           // sys_exit
    svc     #0
