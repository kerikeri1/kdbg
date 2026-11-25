/*
 * kdbg - minimal Linux x86_64 debugger based on ptrace(2)
 * Milestone 1: target launch, registers, single-step, continue.
 * Milestone 2: software breakpoints (int3 / 0xCC).
 * Milestone 3: memory read/write (x, set).
 * Milestone 4: ELF symbols (b main, x secret, <func+off> in output).
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

#include "elf.h"

static pid_t child;

static int wait_child(void);

/* Signal that stopped the tracee and has not been delivered yet (0 = none).
 * When the tracee receives a signal, the kernel stops it BEFORE delivering
 * the signal and notifies us. We must pass it back on the next PTRACE_CONT /
 * PTRACE_SINGLESTEP, otherwise the signal is discarded. */
static int pending_signal;

static void print_location(uint64_t addr);

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
         "  syms           list function symbols\n"
         "  h | help       this message\n"
         "  q | quit       kill the target and exit\n"
         "<loc> is an address or a symbol name");

}

static void run_debugger(const char *path)
{
    char line[256];

    if (wait_child() < 0)  /* first stop: SIGTRAP after execve */
        return;
    printf("[*] target started, pid %d (stopped at execve)\n", child);

    int n = elf_load_symbols(path, child);
    if (n >= 0)
        printf("[*] loaded %d symbols from %s\n", n, path);

    for (;;) {
        printf("kdbg> ");
        fflush(stdout);
        if (!fgets(line, sizeof line, stdin))
            break;
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
            struct user_regs_struct r;
            ptrace(PTRACE_GETREGS, child, NULL, &r);
            printf("rip = ");
            print_location(r.rip);
            putchar('\n');
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
        } else if (!strcmp(line, "syms")) {
            elf_list_functions();
        } else if (!strcmp(line, "h") || !strcmp(line, "help")) {
            help();
        } else if (!strcmp(line, "q") || !strcmp(line, "quit")) {
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
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

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <program> [args...]\n", argv[0]);
        return 1;
    }

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

    run_debugger(argv[1]);
    elf_free_symbols();
    return 0;
}
