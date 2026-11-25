CC      = gcc
CFLAGS  = -Wall -Wextra -g -O0

all: kdbg test/hello

kdbg: src/main.c
	$(CC) $(CFLAGS) -o $@ $^

test/hello: test/hello.c
	$(CC) -g -O0 -no-pie -o $@ $^

clean:
	rm -f kdbg test/hello

.PHONY: all clean
