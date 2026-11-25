# kdbg

Debugger minimale per Linux x86_64 scritto in C, basato su `ptrace(2)`.
È un progetto didattico: lo scopo è capire come funzionano davvero i debugger come GDB.

## Build

```sh
make
./kdbg ./test/hello
```

## Comandi

| Comando | Descrizione |
|---|---|
| `r`, `regs` | mostra i registri |
| `s`, `step` | esegue una singola istruzione |
| `c`, `continue` | riprende l'esecuzione |
| `q`, `quit` | termina il target |

## Roadmap

- [x] **M1** – fork/exec del target, registri, single-step, continue
- [ ] **M2** – breakpoint software (`int3` / `0xCC`) su indirizzo
- [ ] **M3** – lettura/scrittura memoria (`x addr`, `set`)
- [ ] **M4** – simboli: parsing ELF (`.symtab`) → `break main`
- [ ] **M5** – disassembly dell'istruzione corrente (Capstone)
- [ ] **M6** – attach a un processo esistente (`PTRACE_ATTACH`)
- [ ] **M7** – backtrace tramite catena di `rbp`

## Come funziona (M1)

1. `fork()` → il figlio chiama `ptrace(PTRACE_TRACEME)` e poi `execvp()`.
2. Il kernel ferma il figlio con `SIGTRAP` subito dopo `execve`.
3. Il padre (il debugger) usa `PTRACE_GETREGS`, `PTRACE_SINGLESTEP`, `PTRACE_CONT` e `waitpid()` per controllarlo.
4. L'ASLR viene disattivato nel figlio (`personality(ADDR_NO_RANDOMIZE)`) per avere indirizzi stabili.
