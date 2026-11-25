CC      = gcc
CFLAGS  = -Wall -Wextra -g -O0

all: kdbg test/hello test/loop test/vars test/crash

kdbg: src/main.c
	$(CC) $(CFLAGS) -o $@ $^

test/hello: test/hello.c
	$(CC) -g -O0 -no-pie -o $@ $^

test/loop: test/loop.c
	$(CC) -g -O0 -no-pie -o $@ $^

test/vars: test/vars.c
	$(CC) -g -O0 -no-pie -o $@ $^

test/crash: test/crash.c
	$(CC) -g -O0 -no-pie -o $@ $^

clean:
	rm -f kdbg test/hello test/loop test/vars test/crash

.PHONY: all clean
