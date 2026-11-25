/*
 * elf.h - minimal ELF64 symbol loader for kdbg
 */
#ifndef KDBG_ELF_H
#define KDBG_ELF_H

#include <stdint.h>
#include <sys/types.h>

struct symbol {
    char     *name;
    uint64_t  addr;   /* runtime address (load base already applied) */
    uint64_t  size;
    int       is_func;
};

/*
 * Load function and object symbols from the ELF file at path.
 * For PIE binaries (ET_DYN) the load base of the running process pid is
 * read from /proc/<pid>/maps and added to every address.
 * Returns the number of symbols loaded, or -1 on error.
 */
int elf_load_symbols(const char *path, pid_t pid);

/* Find a symbol by name. Returns NULL if not found. */
const struct symbol *elf_find_symbol(const char *name);

/* Find the symbol containing addr (addr in [start, start + size)). */
const struct symbol *elf_symbol_at(uint64_t addr);

/* Print all function symbols. */
void elf_list_functions(void);

void elf_free_symbols(void);

#endif
