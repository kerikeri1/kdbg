#include <stdio.h>

int add(int a, int b) { return a + b; }

int main(void)
{
    int sum = 0;
    for (int i = 0; i < 3; i++)
        sum = add(sum, i);
    printf("sum = %d\n", sum);
    return 0;
}
