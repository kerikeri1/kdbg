#include <stdio.h>

int level3(int x) { return x * 2; }
int level2(int x) { return level3(x + 1); }
int level1(int x) { return level2(x + 1); }

int main(void)
{
    printf("result = %d\n", level1(1));
    return 0;
}
