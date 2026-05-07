/*
 * realworld.c — Qsafe VMP 真实环境加固案例
 *
 * 模拟一个商用 NDK SDK 的关键路径：
 *   - 一个对称加密函数（rounds 多）
 *   - 一段 SIMD 哈希
 *   - 一个 syscall 包装
 *   - 一个简单的 license 校验
 *
 * 编译：
 *   $NDK/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android35-clang \
 *       -O2 -fPIC -shared realworld.c -o librealworld.so
 *
 * 加固：
 *   ./vmp protect ./librealworld.so -o realworld.qvmp --level heavy
 *   ./vmp rewrite ./librealworld.so realworld.qvmp -o librealworld-vmp.so
 *
 * 运行：
 *   QVMP_FLAGS=anti_debug+anti_hook+anti_inject+anti_emulator \
 *   QVMP_RESPONSE=corrupt \
 *       LD_PRELOAD=./libqvmp_runtime.so ./test_harness
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ============== 1) 对称加密内核（多轮 ARX 风格） ============== */
__attribute__((noinline))
uint64_t enc_round(uint64_t state, uint64_t key) {
    state ^= key;
    state = (state << 13) | (state >> 51);
    state += 0x9E3779B97F4A7C15ULL;
    state ^= state >> 27;
    state *= 0xBF58476D1CE4E5B9ULL;
    return state;
}

__attribute__((noinline))
uint64_t encrypt(uint64_t input, uint64_t key) {
    uint64_t s = input;
    for (int i = 0; i < 16; i++) {
        s = enc_round(s, key + i * 0xDEADBEEF12345678ULL);
    }
    return s;
}

/* ============== 2) NEON 整数向量哈希 ============== */
/* 注：故意写成 ARM64 编译器倾向于发射 NEON 整数 ADD/MUL 的形态 */
__attribute__((noinline))
uint32_t simd_hash(const uint32_t *data, size_t n) {
    uint32_t acc[4] = {0};
    for (size_t i = 0; i < n; i += 4) {
        acc[0] = acc[0] * 31u + data[i + 0];
        acc[1] = acc[1] * 31u + data[i + 1];
        acc[2] = acc[2] * 31u + data[i + 2];
        acc[3] = acc[3] * 31u + data[i + 3];
    }
    return acc[0] ^ acc[1] ^ acc[2] ^ acc[3];
}

/* ============== 3) Syscall 包装 ============== */
/* getpid()，故意走 inline syscall 不通过 libc */
__attribute__((noinline))
long my_getpid(void) {
    long ret;
#if defined(__aarch64__)
    register long x8 __asm__("x8") = 172; /* SYS_getpid */
    register long x0 __asm__("x0");
    __asm__ volatile ("svc #0" : "=r"(x0) : "r"(x8) : "memory");
    ret = x0;
#else
    ret = -1;
#endif
    return ret;
}

/* ============== 4) License 校验（典型反破解目标） ============== */
__attribute__((noinline))
int verify_license(const char *key, size_t len) {
    /* 期望：encrypt(0xCAFEBABEDEADBEEF, sha-ish(key)) 的低 16 bit == 0xC0FE */
    uint64_t h = 0;
    for (size_t i = 0; i < len; i++) {
        h = h * 1313 + (uint8_t)key[i];
    }
    uint64_t e = encrypt(0xCAFEBABEDEADBEEFULL, h);
    return ((e & 0xFFFF) == 0xC0FE) ? 1 : 0;
}

/* ============== 5) 综合入口 ============== */
__attribute__((noinline))
uint64_t pipeline(uint64_t seed, const uint32_t *data, size_t n,
                  const char *license, size_t licl) {
    if (!verify_license(license, licl)) {
        return 0;
    }
    uint32_t h = simd_hash(data, n);
    uint64_t e = encrypt(seed ^ h, (uint64_t)h * 0xCAFEBABEULL);
    long pid = my_getpid();
    return e ^ (uint64_t)pid;
}
