kdbg

A minimal Linux x86_64 debugger written in C, based on ptrace(2). This is a learning project: the goal is to understand how debuggers like GDB actually work.

Build
sh
make
./kdbg ./test/hello
Commands
Command	Description
r, regs	show registers
s, step	execute a single instruction
c, continue	resume execution
h, help	show help
q, quit	kill the target and exit
Roadmap
[x] M1 – fork/exec the target, registers, single-step, continue
[ ] M2 – software breakpoints (int3 / 0xCC) at an address
[ ] M3 – memory read/write (x addr, set)
[ ] M4 – symbols: ELF parsing (.symtab) → break main
[ ] M5 – disassembly of the current instruction (Capstone)
[ ] M6 – attach to a running process (PTRACE_ATTACH)
[ ] M7 – backtrace by walking the rbp chain
How it works (M1)
fork() → the child calls ptrace(PTRACE_TRACEME) and then execvp().
The kernel stops the child with SIGTRAP right after execve.
The parent (the debugger) controls it with PTRACE_GETREGS, PTRACE_SINGLESTEP, PTRACE_CONT and waitpid().
ASLR is disabled in the child (personality(ADDR_NO_RANDOMIZE)) so addresses stay stable between runs.
