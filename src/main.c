/*
 * kdbg - minimal Linux x86_64 debugger based on ptrace(2)
 * Milestone 1: target launch, registers, single-step, continue.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/personality.h>

static pid_t child;

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
            ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
            if (wait_child() < 0) return;
            struct user_regs_struct r;
            ptrace(PTRACE_GETREGS, child, NULL, &r);
            printf("rip = 0x%llx\n", r.rip);
        } else if (!strcmp(line, "c") || !strcmp(line, "continue")) {
            ptrace(PTRACE_CONT, child, NULL, NULL);
            if (wait_child() < 0) return;
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
