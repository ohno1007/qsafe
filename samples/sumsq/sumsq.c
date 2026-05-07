// sumsq.c — freestanding aarch64 Linux/Android 程序
//
// 计算 1^2 + 2^2 + ... + N^2，把结果转字符串后写到 stdout，并以结果作为 exit code。
// 不依赖 libc，全部通过 svc #0 直接发系统调用，便于做 VMP 全程序虚拟化演示。
//
// 编译（NDK，Windows）:
//   set NDK=D:\android-ndk-r29-beta4
//   %NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang ^
//        -O1 -fno-stack-protector -nostdlib -static -fno-pic -no-pie ^
//        -o sumsq sumsq.c
//
// 期望: ./sumsq 输出 "385\n"，退出码 = 385 & 0xFF = 129

typedef unsigned long u64;
typedef long ssize_t;

#define SYS_write 64
#define SYS_exit  93

static inline long syscall1(long n, long a0) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    __asm__ volatile ("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

static inline long syscall3(long n, long a0, long a1, long a2) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    __asm__ volatile ("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

static int sum_of_squares(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++) s += i * i;
    return s;
}

static int int_to_str(int n, char *buf) {
    if (n == 0) { buf[0] = '0'; return 1; }
    char tmp[12];
    int t = 0;
    while (n > 0) { tmp[t++] = (char)('0' + (n % 10)); n /= 10; }
    int i = 0;
    while (t > 0) buf[i++] = tmp[--t];
    return i;
}

void _start(void) {
    int r = sum_of_squares(10);
    char buf[16];
    int len = int_to_str(r, buf);
    buf[len++] = '\n';
    syscall3(SYS_write, 1, (long)buf, (long)len);
    syscall1(SYS_exit, r);
    while (1) {}
}
