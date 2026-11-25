/*
 * kdbg - debugger minimale per Linux x86_64 basato su ptrace(2)
 * Milestone 1: avvio del target, registri, single-step, continue.
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

/* Aspetta il figlio e ritorna 0 se è ancora vivo (stoppato), -1 se è terminato */
static int wait_child(void)
{
    int status;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }
    if (WIFEXITED(status)) {
        printf("[*] processo terminato, exit code %d\n", WEXITSTATUS(status));
        return -1;
    }
    if (WIFSIGNALED(status)) {
        printf("[*] processo ucciso dal segnale %d\n", WTERMSIG(status));
        return -1;
    }
    if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP)
        printf("[*] stop per segnale %d\n", WSTOPSIG(status));
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
    puts("comandi:\n"
         "  r | regs       mostra i registri\n"
         "  s | step       esegue una singola istruzione\n"
         "  c | continue   riprende l'esecuzione\n"
         "  h | help       questo messaggio\n"
         "  q | quit       termina il target ed esce");
}

static void run_debugger(void)
{
    char line[256];

    if (wait_child() < 0)  /* primo stop: SIGTRAP dopo execve */
        return;
    printf("[*] target avviato, pid %d (stop su execve)\n", child);

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
            printf("comando sconosciuto: %s (prova 'help')\n", line);
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "uso: %s <programma> [argomenti...]\n", argv[0]);
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        /* Figlio: chiede di essere tracciato, disattiva ASLR, esegue il target */
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
