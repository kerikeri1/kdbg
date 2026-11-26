CC      = gcc
CFLAGS  = -Wall -Wextra -g -O0
LDLIBS  = -lcapstone

all: kdbg test/hello test/loop test/vars test/crash test/vars_pie test/nested test/sleeper test/recursive test/watch test/files

kdbg: src/main.c src/elf.c src/elf.h
	$(CC) $(CFLAGS) -o $@ src/main.c src/elf.c $(LDLIBS)

test/hello: test/hello.c
	$(CC) -g -O0 -no-pie -o $@ $^

test/loop: test/loop.c
	$(CC) -g -O0 -no-pie -o $@ $^

test/vars: test/vars.c
	$(CC) -g -O0 -no-pie -o $@ $^

test/crash: test/crash.c
	$(CC) -g -O0 -no-pie -o $@ $^

test/nested: test/nested.c
	$(CC) -g -O0 -no-pie -o $@ $^

test/recursive: test/recursive.c
	$(CC) -g -O0 -no-pie -o $@ $^

test/watch: test/watch.c
	$(CC) -g -O0 -no-pie -o $@ $^

test/files: test/files.c
	$(CC) -g -O0 -no-pie -o $@ $^

test/sleeper: test/sleeper.c
	$(CC) -g -O0 -no-pie -o $@ $^

# Same program built as PIE, to test the load base handling
test/vars_pie: test/vars.c
	$(CC) -g -O0 -pie -fPIE -o $@ $^

clean:
	rm -f kdbg test/hello test/loop test/vars test/crash test/vars_pie test/nested test/sleeper test/recursive test/watch test/files

.PHONY: all clean
