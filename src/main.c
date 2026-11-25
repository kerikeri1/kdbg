/*
 * kdbg - minimal Linux x86_64 debugger based on ptrace(2)
 * Milestone 1: target launch, registers, single-step, continue.
 * Milestone 2: software breakpoints (int3 / 0xCC).
 * Milestone 3: memory read/write (x, set).
 * Milestone 4: ELF symbols (b main, x secret, <func+off> in output).
 * Milestone 5: disassembly with Capstone (dis, current instruction on stop).
 * Milestone 6: attach to a running process (kdbg -p <pid>).
 * Milestone 7: backtrace by walking the rbp chain (bt).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/personality.h>
#include <signal.h>

#include <capstone/capstone.h>

#include "elf.h"

static pid_t child;
static int attached;  /* 1 if we attached with -p (detach on exit, don't kill) */

/*
 * Ctrl+C while the target is running: stop it and return to the prompt.
 * In launch mode the target shares our terminal and receives SIGINT itself;
 * in attach mode it doesn't, so we stop it with SIGSTOP. Either way the
 * signal is ours and must not be forwarded to the program.
 */
static volatile sig_atomic_t interrupted;

static void on_sigint(int sig)
{
    (void)sig;
    interrupted = 1;
    if (attached)
        kill(child, SIGSTOP);
}

static int wait_child(void);

/* Signal that stopped the tracee and has not been delivered yet (0 = none).
 * When the tracee receives a signal, the kernel stops it BEFORE delivering
 * the signal and notifies us. We must pass it back on the next PTRACE_CONT /
 * PTRACE_SINGLESTEP, otherwise the signal is discarded. */
static int pending_signal;

static void print_location(uint64_t addr);
static void show_current_instruction(void);

static csh cs_handle;  /* Capstone disassembler handle */

/* ---------------------------------------------------------------------------
 * Breakpoints
 *
 * A software breakpoint replaces the first byte of an instruction with 0xCC
 * (the "int3" opcode). When the CPU executes it, the kernel stops the tracee
 * with SIGTRAP and rip points to the byte AFTER the 0xCC (addr + 1).
 * ------------------------------------------------------------------------- */
#define MAX_BREAKPOINTS 16

struct breakpoint {
    uint64_t addr;      /* address where the breakpoint is placed */
    uint8_t  orig_byte; /* original byte overwritten by 0xCC */
    int      enabled;   /* 1 if 0xCC is currently written in memory */
};

static struct breakpoint bps[MAX_BREAKPOINTS];
static int bp_count;

/* Breakpoint we are currently stopped on: its original byte is restored
 * and it must be re-armed (0xCC written back) once we step past it. */
static struct breakpoint *pending_rearm;

static struct breakpoint *find_breakpoint(uint64_t addr)
{
    for (int i = 0; i < bp_count; i++)
        if (bps[i].addr == addr)
            return &bps[i];
    return NULL;
}

/*
 * Write a single byte at addr in the tracee's memory.
 * ptrace only reads/writes whole 8-byte words, so we read the word,
 * replace its lowest byte (x86 is little-endian: the lowest byte is the
 * one at addr) and write it back. The previous byte is stored in *old.
 * Returns 0 on success, -1 on error.
 */
static int write_byte(uint64_t addr, uint8_t byte, uint8_t *old)
{
    errno = 0;  /* PEEKDATA returns the data itself: -1 may be valid */
    long word = ptrace(PTRACE_PEEKDATA, child, (void *)addr, NULL);
    if (errno) {
        perror("PTRACE_PEEKDATA");
        return -1;
    }
    if (old)
        *old = (uint8_t)(word & 0xff);

    long patched = (word & ~0xffL) | byte;
    if (ptrace(PTRACE_POKEDATA, child, (void *)addr, (void *)patched) < 0) {
        perror("PTRACE_POKEDATA");
        return -1;
    }
    return 0;
}

/* Insert a breakpoint at addr. Returns 0 on success, -1 on error. */
static int set_breakpoint(uint64_t addr)
{
    if (bp_count >= MAX_BREAKPOINTS) {
        printf("too many breakpoints (max %d)\n", MAX_BREAKPOINTS);
        return -1;
    }
    if (find_breakpoint(addr)) {
        printf("breakpoint already set at 0x%lx\n", addr);
        return -1;
    }

    uint8_t orig;
    if (write_byte(addr, 0xCC, &orig) < 0)
        return -1;

    bps[bp_count++] = (struct breakpoint){ .addr = addr, .orig_byte = orig, .enabled = 1 };
    printf("breakpoint %d at ", bp_count - 1);
    print_location(addr);
    putchar('\n');
    return 0;
}

/*
 * Called after every stop caused by "continue".
 * If the tracee stopped on one of our breakpoints: restore the original
 * instruction, move rip back by one and remember to re-arm it later.
 */
static void handle_breakpoint_hit(void)
{
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, child, NULL, &r) < 0)
        return;

    /* After executing int3 (1 byte), rip points to addr + 1 */
    struct breakpoint *bp = find_breakpoint(r.rip - 1);
    if (!bp || !bp->enabled)
        return;

    printf("hit breakpoint %ld at ", (long)(bp - bps));
    print_location(bp->addr);
    putchar('\n');

    /* Put the original instruction back */
    if (write_byte(bp->addr, bp->orig_byte, NULL) < 0)
        return;
    bp->enabled = 0;

    /* Rewind rip so the original instruction gets executed */
    r.rip -= 1;
    ptrace(PTRACE_SETREGS, child, NULL, &r);

    pending_rearm = bp;
    show_current_instruction();
}

/*
 * If we are stopped on a breakpoint, execute the original instruction
 * with a single-step and then write 0xCC back, so the breakpoint stays
 * active for the next time (breakpoints are permanent, not one-shot).
 * Returns 0 if the tracee is still alive, -1 if it terminated.
 */
static int step_over_breakpoint(void)
{
    if (!pending_rearm)
        return 0;

    struct breakpoint *bp = pending_rearm;
    pending_rearm = NULL;

    ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
    if (wait_child() < 0)
        return -1;

    if (write_byte(bp->addr, 0xCC, NULL) == 0)
        bp->enabled = 1;
    return 0;
}

/* ---------------------------------------------------------------------------
 * Memory
 * ------------------------------------------------------------------------- */

/*
 * Read len bytes from the tracee starting at addr into buf.
 * ptrace reads 8 bytes at a time, so we read word by word and copy only
 * the bytes we need. Returns 0 on success, -1 on error.
 */
static int read_memory(uint64_t addr, uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, child, (void *)(addr + done), NULL);
        if (errno) {
            printf("cannot read memory at 0x%lx: %s\n", addr + done, strerror(errno));
            return -1;
        }
        size_t chunk = len - done < sizeof word ? len - done : sizeof word;
        memcpy(buf + done, &word, chunk);
        done += chunk;
    }
    return 0;
}

/*
 * Show the bytes we placed 0xCC over with their original value, so the
 * user sees the real program code and not our breakpoints.
 */
static void hide_breakpoints(uint64_t addr, uint8_t *buf, size_t len);

/* x <addr> [count]: hexdump of count bytes (default 32), 16 per line */
static void examine_memory(uint64_t addr, size_t count)
{
    uint8_t buf[256];
    if (count > sizeof buf)
        count = sizeof buf;
    if (read_memory(addr, buf, count) < 0)
        return;
    hide_breakpoints(addr, buf, count);

    for (size_t i = 0; i < count; i += 16) {
        printf("0x%016lx: ", addr + i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < count)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < count; j++)
            putchar(isprint(buf[i + j]) ? buf[i + j] : '.');
        puts("|");
    }
}

/* set <addr> <value>: write a 64-bit value (8 bytes) at addr */
static void set_memory(uint64_t addr, uint64_t value)
{
    if (ptrace(PTRACE_POKEDATA, child, (void *)addr, (void *)value) < 0) {
        printf("cannot write memory at 0x%lx: %s\n", addr, strerror(errno));
        return;
    }
    printf("0x%lx <- 0x%lx\n", addr, value);
}

/* ---------------------------------------------------------------------------
 * Disassembly (Capstone)
 * ------------------------------------------------------------------------- */

#define MAX_INSN_LEN 15  /* longest possible x86 instruction, in bytes */

/*
 * Disassemble count instructions starting at addr.
 * x86 instructions have variable length, so we read count * 15 bytes
 * (the worst case) and let Capstone decode as many as it can.
 * The instruction at the current rip is marked with "=>".
 */
static void disassemble(uint64_t addr, size_t count)
{
    uint8_t code[32 * MAX_INSN_LEN];
    if (count > 32)
        count = 32;

    /*
     * Read word by word and stop at the first unreadable address: near the
     * end of a mapping, count * 15 bytes may go past it, but the bytes we
     * did read can still be disassembled.
     */
    size_t len = 0, want = count * MAX_INSN_LEN;
    while (len < want) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, child, (void *)(addr + len), NULL);
        if (errno)
            break;
        size_t chunk = want - len < sizeof word ? want - len : sizeof word;
        memcpy(code + len, &word, chunk);
        len += chunk;
    }
    if (len == 0) {
        printf("cannot read memory at 0x%lx\n", addr);
        return;
    }
    hide_breakpoints(addr, code, len);  /* show original bytes, not 0xCC */

    struct user_regs_struct r;
    ptrace(PTRACE_GETREGS, child, NULL, &r);

    cs_insn *insn;
    size_t n = cs_disasm(cs_handle, code, len, addr, count, &insn);
    if (n == 0) {
        printf("cannot disassemble at 0x%lx\n", addr);
        return;
    }

    for (size_t i = 0; i < n; i++) {
        printf("%s ", insn[i].address == r.rip ? "=>" : "  ");
        print_location(insn[i].address);
        printf(":\t%s\t%s", insn[i].mnemonic, insn[i].op_str);

        /* For call/jmp to a direct address, show the target symbol */
        if ((insn[i].mnemonic[0] == 'j' || !strcmp(insn[i].mnemonic, "call")) &&
            !strncmp(insn[i].op_str, "0x", 2)) {
            const struct symbol *sym = elf_symbol_at(strtoull(insn[i].op_str, NULL, 16));
            if (sym)
                printf("\t<%s>", sym->name);
        }
        putchar('\n');
    }
    cs_free(insn, n);
}

/* Print the instruction at rip: called after every step and breakpoint hit */
static void show_current_instruction(void)
{
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, child, NULL, &r) == 0)
        disassemble(r.rip, 1);
}

static void list_breakpoints(void)
{
    if (bp_count == 0) {
        puts("no breakpoints");
        return;
    }
    for (int i = 0; i < bp_count; i++)
    {
        printf("%d: ", i);
        print_location(bps[i].addr);
        printf(" %s\n", bps[i].enabled ? "enabled" : "disabled");
    }
}

/* Wait for the child: returns 0 if it is still alive (stopped), -1 if it has terminated */
static int wait_child(void)
{
    int status;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }
    if (WIFEXITED(status)) {
        printf("[*] process exited, exit code %d\n", WEXITSTATUS(status));
        return -1;
    }
    if (WIFSIGNALED(status)) {
        printf("[*] process killed by signal %d\n", WTERMSIG(status));
        return -1;
    }
    pending_signal = 0;
    if (WIFSTOPPED(status) && interrupted &&
        (WSTOPSIG(status) == SIGINT || WSTOPSIG(status) == SIGSTOP)) {
        interrupted = 0;
        printf("\n[*] interrupted\n");
        return 0;
    }
    if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP) {
        /* SIGTRAP is ours (breakpoints, single-step): never forward it */
        pending_signal = WSTOPSIG(status);
        printf("[*] stopped by signal %d (%s), will be delivered on resume\n",
               pending_signal, strsignal(pending_signal));
    }
    return 0;
}

static void print_regs(void)
{
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, child, NULL, &r) < 0) {
        perror("PTRACE_GETREGS");
        return;
    }
    printf("rip 0x%016llx  rsp 0x%016llx  rbp 0x%016llx\n", r.rip, r.rsp, r.rbp);
    printf("rax 0x%016llx  rbx 0x%016llx  rcx 0x%016llx\n", r.rax, r.rbx, r.rcx);
    printf("rdx 0x%016llx  rsi 0x%016llx  rdi 0x%016llx\n", r.rdx, r.rsi, r.rdi);
    printf("r8  0x%016llx  r9  0x%016llx  r10 0x%016llx\n", r.r8, r.r9, r.r10);
    printf("eflags 0x%llx\n", r.eflags);
}

/* Print addr as "0x401126 <show+4>" when it falls inside a known symbol */
static void print_location(uint64_t addr)
{
    const struct symbol *sym = elf_symbol_at(addr);
    if (!sym)
        printf("0x%lx", addr);
    else if (addr == sym->addr)
        printf("0x%lx <%s>", addr, sym->name);
    else
        printf("0x%lx <%s+%lu>", addr, sym->name, addr - sym->addr);
}

/*
 * Parse the first token of str as an address: either a number
 * (0x401126, 4198694) or a symbol name (show, secret).
 * On success stores the address in *addr, sets *rest to the text after
 * the token and returns 0. Returns -1 if the token is missing, -2 if it is
 * an unknown symbol (an error message is already printed).
 */
static int parse_address(const char *str, uint64_t *addr, char **rest)
{
    while (*str == ' ')
        str++;
    if (!*str)
        return -1;

    /* Numbers start with a digit */
    if (isdigit((unsigned char)*str)) {
        char *end;
        *addr = strtoull(str, &end, 0);
        if (rest)
            *rest = end;
        return 0;
    }

    /* Otherwise it is a symbol name: copy the token and look it up */
    char name[128];
    size_t len = strcspn(str, " ");
    if (len >= sizeof name)
        return -1;
    memcpy(name, str, len);
    name[len] = '\0';

    const struct symbol *sym = elf_find_symbol(name);
    if (!sym) {
        printf("unknown symbol: %s\n", name);
        return -2;
    }
    *addr = sym->addr;
    if (rest)
        *rest = (char *)str + len;
    return 0;
}

/* ---------------------------------------------------------------------------
 * Backtrace
 *
 * With frame pointers, every function starts with:
 *     push rbp        ; save the caller's rbp
 *     mov  rbp, rsp   ; rbp now points to the saved rbp
 * so each frame looks like this (the stack grows towards lower addresses):
 *
 *     [rbp + 8]  return address  -> where the caller continues
 *     [rbp]      saved rbp       -> the caller's frame
 *
 * Following saved rbp values walks from the current function up to main.
 * ------------------------------------------------------------------------- */

static int read_u64(uint64_t addr, uint64_t *value)
{
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, child, (void *)addr, NULL);
    if (errno)
        return -1;
    *value = (uint64_t)word;
    return 0;
}

/*
 * Where is the return address of the current function?
 * The rbp chain is only valid after the prologue has run. If we are
 * stopped on the first instructions of a function (typical with
 * "b func"), rbp still belongs to the caller and the return address
 * is found relative to rsp instead.
 */
static int prologue_state(uint64_t rip)
{
    const struct symbol *sym = elf_symbol_at(rip);
    if (!sym || !sym->is_func)
        return 2;  /* unknown: assume the prologue is done */

    uint64_t start = sym->addr;
    uint8_t code[8];
    if (read_memory(start, code, sizeof code) < 0)
        return 2;
    hide_breakpoints(start, code, sizeof code);

    /* skip endbr64 (f3 0f 1e fa) if the compiler added it */
    if (!memcmp(code, "\xf3\x0f\x1e\xfa", 4))
        start += 4;

    if (rip <= start)
        return 0;  /* before push rbp: return address at [rsp] */
    if (rip == start + 1)
        return 1;  /* after push rbp:  return address at [rsp + 8] */
    return 2;      /* prologue done:   use the rbp chain */
}

static void backtrace(void)
{
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, child, NULL, &r) < 0)
        return;

    int depth = 0;
    printf("#%d  ", depth++);
    print_location(r.rip);
    putchar('\n');

    uint64_t rbp = r.rbp;
    uint64_t ret;

    /* Frame 1 may need special handling if we are inside the prologue */
    int state = prologue_state(r.rip);
    if (state < 2) {
        if (read_u64(r.rsp + 8 * state, &ret) < 0)
            return;
        printf("#%d  ", depth++);
        print_location(ret);
        putchar('\n');
        const struct symbol *sym = elf_symbol_at(ret);
        if (sym && !strcmp(sym->name, "main"))
            return;
    }

    while (rbp && depth < 32) {
        uint64_t saved_rbp;
        if (read_u64(rbp, &saved_rbp) < 0 || read_u64(rbp + 8, &ret) < 0)
            break;
        if (!ret)
            break;

        printf("#%d  ", depth++);
        print_location(ret);
        putchar('\n');

        /* stop at main: above it there is only libc startup code */
        const struct symbol *sym = elf_symbol_at(ret);
        if (sym && !strcmp(sym->name, "main"))
            break;

        if (saved_rbp <= rbp)  /* the stack grows down: frames go up */
            break;
        rbp = saved_rbp;
    }
}

/*
 * Leave the tracee as we found it: remove every 0xCC we wrote, then
 * detach (attach mode) or kill it (launch mode).
 */
static void cleanup(void)
{
    if (attached) {
        for (int i = 0; i < bp_count; i++)
            if (bps[i].enabled)
                write_byte(bps[i].addr, bps[i].orig_byte, NULL);
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        printf("[*] detached from pid %d\n", child);
    } else {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
    }
}

static void help(void)
{
    puts("commands:\n"
         "  r | regs       show registers\n"
         "  s | step       execute a single instruction\n"
         "  c | continue   resume execution\n"
         "  b <loc>        set a breakpoint (e.g. b main, b 0x401126)\n"
         "  bl             list breakpoints\n"
         "  x <loc> [n]    dump n bytes of memory (default 32)\n"
         "  set <loc> <v>  write a 64-bit value at loc\n"
         "  dis [loc] [n]  disassemble n instructions (default: 8 from rip)\n"
         "  bt             backtrace (call stack)\n"
         "  syms           list function symbols\n"
         "  h | help       this message\n"
         "  q | quit       kill the target (or detach, with -p) and exit\n"
         "<loc> is an address or a symbol name");

}

static void run_debugger(const char *path)
{
    char line[256];

    if (attached) {
        /*
         * PTRACE_ATTACH stops the process by sending it SIGSTOP. We wait
         * for that stop directly (not with wait_child) because this
         * SIGSTOP is ours: it must not be forwarded on the next continue,
         * or the process would stop again.
         */
        if (waitpid(child, NULL, 0) < 0) {
            perror("waitpid");
            return;
        }
        printf("[*] attached to pid %d\n", child);
    } else {
        if (wait_child() < 0)  /* first stop: SIGTRAP after execve */
            return;
        printf("[*] target started, pid %d (stopped at execve)\n", child);
    }

    int n = elf_load_symbols(path, child);
    if (n >= 0)
        printf("[*] loaded %d symbols from %s\n", n, path);

    for (;;) {
        printf("kdbg> ");
        fflush(stdout);
        if (!fgets(line, sizeof line, stdin)) {
            cleanup();  /* Ctrl+D */
            return;
        }
        line[strcspn(line, "\n")] = '\0';

        if (!strcmp(line, "r") || !strcmp(line, "regs")) {
            print_regs();
        } else if (!strcmp(line, "s") || !strcmp(line, "step")) {
            if (pending_rearm) {
                /* the single-step is done by step_over_breakpoint() */
                if (step_over_breakpoint() < 0) return;
            } else {
                ptrace(PTRACE_SINGLESTEP, child, NULL, (void *)(long)pending_signal);
                if (wait_child() < 0) return;
            }
            show_current_instruction();
        } else if (!strcmp(line, "c") || !strcmp(line, "continue")) {
            if (step_over_breakpoint() < 0) return;
            ptrace(PTRACE_CONT, child, NULL, (void *)(long)pending_signal);
            if (wait_child() < 0) return;
            handle_breakpoint_hit();
        } else if (!strcmp(line, "b") || !strncmp(line, "b ", 2)) {
            uint64_t addr;
            int rc = parse_address(line + 1, &addr, NULL);
            if (rc == -1)
                puts("usage: b <addr|symbol>");
            else if (rc == 0)
                set_breakpoint(addr);
        } else if (!strcmp(line, "bl")) {
            list_breakpoints();
        } else if (!strcmp(line, "x") || !strncmp(line, "x ", 2)) {
            uint64_t addr;
            char *end;
            int rc = parse_address(line + 1, &addr, &end);
            if (rc == -1) {
                puts("usage: x <addr|symbol> [count]");
            } else if (rc == 0) {
                size_t count = strtoul(end, NULL, 0);
                examine_memory(addr, count ? count : 32);
            }
        } else if (!strcmp(line, "set") || !strncmp(line, "set ", 4)) {
            uint64_t addr;
            char *end1, *end2;
            int rc = parse_address(line + 3, &addr, &end1);
            if (rc == -1) {
                puts("usage: set <addr|symbol> <value>");
            } else if (rc == 0) {
                uint64_t value = strtoull(end1, &end2, 0);
                if (end2 == end1)
                    puts("usage: set <addr|symbol> <value>");
                else
                    set_memory(addr, value);
            }
        } else if (!strcmp(line, "dis") || !strncmp(line, "dis ", 4)) {
            /* dis [loc] [n]: default is 8 instructions from rip */
            uint64_t addr;
            char *end = line + 3;
            int rc = parse_address(line + 3, &addr, &end);
            if (rc == -1) {
                struct user_regs_struct r;
                ptrace(PTRACE_GETREGS, child, NULL, &r);
                addr = r.rip;
                rc = 0;
            }
            if (rc == 0) {
                size_t count = strtoul(end, NULL, 0);
                disassemble(addr, count ? count : 8);
            }
        } else if (!strcmp(line, "bt")) {
            backtrace();
        } else if (!strcmp(line, "syms")) {
            elf_list_functions();
        } else if (!strcmp(line, "h") || !strcmp(line, "help")) {
            help();
        } else if (!strcmp(line, "q") || !strcmp(line, "quit")) {
            cleanup();
            return;
        } else if (line[0]) {
            printf("unknown command: %s (try 'help')\n", line);
        }
    }
}

static void hide_breakpoints(uint64_t addr, uint8_t *buf, size_t len)
{
    for (int i = 0; i < bp_count; i++)
        if (bps[i].enabled && bps[i].addr >= addr && bps[i].addr < addr + len)
            buf[bps[i].addr - addr] = bps[i].orig_byte;
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s <program> [args...]\n"
                    "       %s -p <pid>\n", prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    char exe_path[4096];
    const char *path;

    if (!strcmp(argv[1], "-p")) {
        /* Attach mode: trace a process that is already running */
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }
        child = atoi(argv[2]);
        if (ptrace(PTRACE_ATTACH, child, NULL, NULL) < 0) {
            perror("PTRACE_ATTACH");
            if (errno == EPERM)
                fprintf(stderr, "hint: check /proc/sys/kernel/yama/ptrace_scope "
                                "(1 = only root or a parent can attach)\n");
            return 1;
        }
        attached = 1;

        /* The executable of a running process is /proc/<pid>/exe */
        char link[64];
        snprintf(link, sizeof link, "/proc/%d/exe", child);
        ssize_t len = readlink(link, exe_path, sizeof exe_path - 1);
        exe_path[len > 0 ? len : 0] = '\0';
        path = exe_path;
    } else {
        /* Launch mode: fork + exec the target */
        child = fork();
        if (child < 0) {
            perror("fork");
            return 1;
        }

        if (child == 0) {
            /* Child: request tracing, disable ASLR, exec the target */
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
                perror("PTRACE_TRACEME");
                _exit(1);
            }
            personality(ADDR_NO_RANDOMIZE);
            execvp(argv[1], &argv[1]);
            perror("execvp");
            _exit(1);
        }
        path = argv[1];
    }

    /* SA_RESTART: waitpid is restarted after the handler and then sees the stop */
    struct sigaction sa = { .sa_handler = on_sigint, .sa_flags = SA_RESTART };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK) {
        fprintf(stderr, "cannot initialize Capstone\n");
        return 1;
    }

    run_debugger(path);

    cs_close(&cs_handle);
    elf_free_symbols();
    return 0;
}
