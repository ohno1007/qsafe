// fpdemo.c — 用浮点 + 原子操作的 freestanding 程序
// 计算 (1.5 + 2.5 + 3.5 + ... + 10.5) * 2 / 3 然后 atomic add 到 counter，最后 exit(int(result))
//
// 编译:
//   set NDK=D:\android-ndk-r29-beta4
//   %NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd ^
//        -O1 -fno-stack-protector -nostdlib -static -fno-pic -no-pie ^
//        -o fpdemo fpdemo.c
// 期望: exit 40 (= int(60.0 * 2 / 3))
//   sum = 1.5+2.5+...+10.5 = 60.0
//   60 * 2 / 3 = 40

typedef long ssize_t;

#define SYS_exit  93

static inline long syscall1(long n, long a0) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    __asm__ volatile ("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

__attribute__((noinline))
double sum_doubles(double *arr, int n) {
    double s = 0.0;
    for (int i = 0; i < n; i++) {
        s += arr[i];
    }
    return s;
}

__attribute__((noinline))
double scale(double v, double a, double b) {
    return (v * a) / b;
}

void _start(void) {
    double arr[10] = { 1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5, 9.5, 10.5 };
    double s = sum_doubles(arr, 10);          // 60.0
    double r = scale(s, 2.0, 3.0);            // 40.0

    // atomic add counter
    static volatile long counter = 0;
    long delta = (long)r;
    __atomic_fetch_add(&counter, delta, __ATOMIC_SEQ_CST);

    syscall1(SYS_exit, counter);
    while (1) {}
}
