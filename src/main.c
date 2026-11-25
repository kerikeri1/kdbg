/*
 * kdbg - minimal Linux x86_64 debugger based on ptrace(2)
 * Milestone 1: target launch, registers, single-step, continue.
 * Milestone 2: software breakpoints (int3 / 0xCC).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/personality.h>

static pid_t child;

static int wait_child(void);

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
    printf("breakpoint %d at 0x%lx\n", bp_count - 1, addr);
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

    printf("hit breakpoint %ld at 0x%lx\n", (long)(bp - bps), bp->addr);

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

static void list_breakpoints(void)
{
    if (bp_count == 0) {
        puts("no breakpoints");
        return;
    }
    for (int i = 0; i < bp_count; i++)
        printf("%d: 0x%lx %s\n", i, bps[i].addr, bps[i].enabled ? "enabled" : "disabled");
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
    if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP)
        printf("[*] stopped by signal %d\n", WSTOPSIG(status));
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

static void help(void)
{
    puts("commands:\n"
         "  r | regs       show registers\n"
         "  s | step       execute a single instruction\n"
         "  c | continue   resume execution\n"
         "  b <addr>       set a breakpoint (e.g. b 0x401136)\n"
         "  bl             list breakpoints\n"
         "  h | help       this message\n"
         "  q | quit       kill the target and exit");
}

static void run_debugger(void)
{
    char line[256];

    if (wait_child() < 0)  /* first stop: SIGTRAP after execve */
        return;
    printf("[*] target started, pid %d (stopped at execve)\n", child);

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
                ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
                if (wait_child() < 0) return;
            }
            struct user_regs_struct r;
            ptrace(PTRACE_GETREGS, child, NULL, &r);
            printf("rip = 0x%llx\n", r.rip);
        } else if (!strcmp(line, "c") || !strcmp(line, "continue")) {
            if (step_over_breakpoint() < 0) return;
            ptrace(PTRACE_CONT, child, NULL, NULL);
            if (wait_child() < 0) return;
            handle_breakpoint_hit();
        } else if (!strncmp(line, "b ", 2)) {
            char *end;
            uint64_t addr = strtoull(line + 2, &end, 0);
            if (end == line + 2)
                puts("usage: b <addr>");
            else
                set_breakpoint(addr);
        } else if (!strcmp(line, "bl")) {
            list_breakpoints();
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

    run_debugger();
    return 0;
}
