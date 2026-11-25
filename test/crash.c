#include <stdio.h>

int main(void)
{
    int *p = NULL;
    puts("about to crash...");
    fflush(stdout);
    *p = 42;            /* SIGSEGV */
    puts("never printed");
    return 0;
}
