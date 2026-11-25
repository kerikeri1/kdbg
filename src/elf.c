/*
 * elf.c - minimal ELF64 symbol loader for kdbg
 *
 * Layout of an ELF file (the parts we use):
 *
 *   +------------------+  offset 0
 *   | ELF header       |  -> e_shoff: where the section header table starts
 *   +------------------+     e_shnum: how many section headers there are
 *   | ...              |
 *   | .symtab          |  array of Elf64_Sym (name offset, value, size, type)
 *   | .strtab          |  the symbol names, as NUL-terminated strings
 *   | ...              |
 *   +------------------+
 *   | section headers  |  one Elf64_Shdr per section (type, offset, size, link)
 *   +------------------+
 *
 * A symbol's name is not stored in the symbol itself: st_name is an offset
 * into the string table, which is the section pointed to by sh_link.
 */
#define _GNU_SOURCE
#include "elf.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct symbol *symbols;
static int sym_count;

/* Read the whole file into memory. Returns NULL on error. */
static uint8_t *read_file(const char *path, size_t *size)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    uint8_t *data = malloc(len);
    if (data && fread(data, 1, len, f) != (size_t)len) {
        free(data);
        data = NULL;
    }
    fclose(f);
    *size = len;
    return data;
}

/*
 * PIE binaries are compiled as if they were loaded at address 0: the
 * kernel picks the real base at runtime. The first line of
 * /proc/<pid>/maps is the first mapping of the executable, i.e. its base.
 */
static uint64_t get_load_base(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    unsigned long base = 0;
    if (fscanf(f, "%lx-", &base) != 1)
        base = 0;
    fclose(f);
    return base;
}

static int cmp_addr(const void *a, const void *b)
{
    const struct symbol *x = a, *y = b;
    return (x->addr > y->addr) - (x->addr < y->addr);
}

int elf_load_symbols(const char *path, pid_t pid)
{
    size_t size;
    uint8_t *data = read_file(path, &size);
    if (!data)
        return -1;

    Elf64_Ehdr *eh = (Elf64_Ehdr *)data;

    /* 1. Check the magic bytes "\x7fELF" and that it is a 64-bit file */
    if (size < sizeof *eh || memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "%s: not a 64-bit ELF file\n", path);
        free(data);
        return -1;
    }

    /* 2. PIE (ET_DYN): addresses are relative, add the runtime base */
    uint64_t base = (eh->e_type == ET_DYN) ? get_load_base(pid) : 0;

    /* 3. Walk the section headers looking for the symbol table */
    Elf64_Shdr *sh = (Elf64_Shdr *)(data + eh->e_shoff);
    Elf64_Shdr *symtab = NULL;
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type == SHT_SYMTAB) {
            symtab = &sh[i];
            break;
        }
    }
    if (!symtab) {
        fprintf(stderr, "%s: no .symtab (binary is stripped?)\n", path);
        free(data);
        return -1;
    }

    /* 4. sh_link of the symbol table is the index of its string table */
    Elf64_Shdr *strtab = &sh[symtab->sh_link];
    const char *names = (const char *)(data + strtab->sh_offset);

    Elf64_Sym *syms = (Elf64_Sym *)(data + symtab->sh_offset);
    int n = symtab->sh_size / sizeof(Elf64_Sym);

    symbols = calloc(n, sizeof *symbols);
    sym_count = 0;

    /* 5. Keep only defined functions and variables */
    for (int i = 0; i < n; i++) {
        int type = ELF64_ST_TYPE(syms[i].st_info);
        if ((type != STT_FUNC && type != STT_OBJECT) ||
            syms[i].st_shndx == SHN_UNDEF || syms[i].st_value == 0)
            continue;

        symbols[sym_count++] = (struct symbol){
            .name    = strdup(names + syms[i].st_name),
            .addr    = base + syms[i].st_value,
            .size    = syms[i].st_size,
            .is_func = (type == STT_FUNC),
        };
    }

    /* Sort by address so "syms" prints them in memory order */
    qsort(symbols, sym_count, sizeof *symbols, cmp_addr);

    free(data);
    return sym_count;
}

const struct symbol *elf_find_symbol(const char *name)
{
    for (int i = 0; i < sym_count; i++)
        if (!strcmp(symbols[i].name, name))
            return &symbols[i];
    return NULL;
}

const struct symbol *elf_symbol_at(uint64_t addr)
{
    for (int i = 0; i < sym_count; i++) {
        const struct symbol *s = &symbols[i];
        if (addr >= s->addr && addr < s->addr + (s->size ? s->size : 1))
            return s;
    }
    return NULL;
}

void elf_list_functions(void)
{
    for (int i = 0; i < sym_count; i++)
        if (symbols[i].is_func)
            printf("0x%016lx  %s\n", symbols[i].addr, symbols[i].name);
}

void elf_free_symbols(void)
{
    for (int i = 0; i < sym_count; i++)
        free(symbols[i].name);
    free(symbols);
    symbols = NULL;
    sym_count = 0;
}
