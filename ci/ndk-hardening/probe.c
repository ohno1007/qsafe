#ifndef EXPECT_FORTIFY
#define EXPECT_FORTIFY 2
#endif
#if !defined(_FORTIFY_SOURCE) || _FORTIFY_SOURCE < EXPECT_FORTIFY
#error "Missing source fortification"
#endif

#include <unistd.h>

int main(void) {
    char buffer[32];
    // The request is always in bounds, but is not a compile-time constant at the call.
    volatile size_t requested = sizeof(buffer);
    ssize_t n = read(STDIN_FILENO, buffer, requested);
    return n > 0 && buffer[0] == '\n';
}
