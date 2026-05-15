// fpdemo_glibc.c — same FP math but dynamic glibc, so we can DT_NEEDED in qvmp runtime.
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
double sum_doubles(double *arr, int n) {
    double s = 0.0;
    for (int i = 0; i < n; i++) s += arr[i];
    return s;
}

__attribute__((noinline))
double scale(double v, double a, double b) {
    return (v * a) / b;
}

int main(void) {
    double arr[10] = { 1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5, 9.5, 10.5 };
    double s = sum_doubles(arr, 10);           // 60.0
    double r = scale(s, 2.0, 3.0);             // 40.0
    printf("sum=%g scale=%g exit=%d\n", s, r, (int)r);
    return (int)r;
}
