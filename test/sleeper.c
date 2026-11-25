#include <stdio.h>
#include <unistd.h>

long counter = 0;

void tick(void)
{
    counter++;
    printf("[pid %d] tick %ld\n", getpid(), counter);
    fflush(stdout);
}

int main(void)
{
    for (;;) {
        tick();
        sleep(1);
    }
}
