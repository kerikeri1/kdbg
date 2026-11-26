#include <stdio.h>

long balance = 100;

void deposit(long amount)  { balance += amount; }
void withdraw(long amount) { balance -= amount; }
long check(void)           { return balance; }   /* read only */

int main(void)
{
    deposit(50);
    check();
    withdraw(30);
    deposit(5);
    printf("balance = %ld\n", balance);
    return 0;
}
