// multifn.c —— freestanding aarch64 多函数程序
// 用 -fno-inline 让 helpers 保留为独立函数符号，触发跨函数 BL → CallRegion。
//
// 编译：
//   set NDK=D:\android-ndk-r29-beta4
//   %NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd ^
//        -O1 -fno-inline -fno-stack-protector -nostdlib -static -fno-pic -no-pie ^
//        -o multifn multifn.c
//
// 程序流程：
//   _start → call sum_of_squares(10) → call write_int(result) → exit(result)
// 期望输出 "385\n"，退出码 129。

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

__attribute__((noinline))
int sum_of_squares(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++) s += i * i;
    return s;
}

__attribute__((noinline))
int write_int(int n) {
    char buf[16];
    int len = 0;
    if (n == 0) { buf[len++] = '0'; }
    else {
        char tmp[12];
        int t = 0;
        int x = n;
        while (x > 0) { tmp[t++] = (char)('0' + (x % 10)); x /= 10; }
        while (t > 0) buf[len++] = tmp[--t];
    }
    buf[len++] = '\n';
    syscall3(SYS_write, 1, (long)buf, (long)len);
    return n;
}

void _start(void) {
    int r = sum_of_squares(10);
    write_int(r);
    syscall1(SYS_exit, r);
    while (1) {}
}
