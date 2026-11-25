#include <stdio.h>

long secret = 42;
char message[] = "hello from kdbg!";

void show(void)
{
    printf("secret = %ld, message = %s\n", secret, message);
}

int main(void)
{
    show();
    show();
    return 0;
}
