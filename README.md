# kdbg

A minimal Linux x86_64 debugger written in C, based on `ptrace(2)`.
This is a learning project: the goal is to understand how debuggers like GDB actually work.

## Build

```sh
make
./kdbg ./test/hello
```

## Commands

| Command | Description |
|---|---|
| `r`, `regs` | show registers |
| `s`, `step` | execute a single instruction |
| `c`, `continue` | resume execution |
| `b <addr>` | set a breakpoint (e.g. `b 0x401136`) |
| `bl` | list breakpoints |
| `h`, `help` | show help |
| `q`, `quit` | kill the target and exit |

## Roadmap

- [x] **M1** – fork/exec the target, registers, single-step, continue
- [x] **M2** – software breakpoints (`int3` / `0xCC`) at an address
- [ ] **M3** – memory read/write (`x addr`, `set`)
- [ ] **M4** – symbols: ELF parsing (`.symtab`) → `break main`
- [ ] **M5** – disassembly of the current instruction (Capstone)
- [ ] **M6** – attach to a running process (`PTRACE_ATTACH`)
- [ ] **M7** – backtrace by walking the `rbp` chain

## How it works (M1)

1. `fork()` → the child calls `ptrace(PTRACE_TRACEME)` and then `execvp()`.
2. The kernel stops the child with `SIGTRAP` right after `execve`.
3. The parent (the debugger) controls it with `PTRACE_GETREGS`, `PTRACE_SINGLESTEP`, `PTRACE_CONT` and `waitpid()`.
4. ASLR is disabled in the child (`personality(ADDR_NO_RANDOMIZE)`) so addresses stay stable between runs.

## How it works (M2)

1. `b <addr>` reads the 8-byte word at `addr` (`PTRACE_PEEKDATA`), saves its lowest byte and replaces it with `0xCC` (`int3`) using `PTRACE_POKEDATA`.
2. When the CPU executes `int3`, the kernel stops the tracee with `SIGTRAP`; `rip` now points to `addr + 1`.
3. The debugger restores the original byte and sets `rip = addr` (`PTRACE_SETREGS`).
4. On the next `step`/`continue` it single-steps the original instruction and writes `0xCC` back, so the breakpoint stays active.

Try it:

```sh
nm test/loop | grep -w add    # find the address of add()
./kdbg ./test/loop
kdbg> b 0x401136
kdbg> c                       # hit 3 times, once per loop iteration
```
