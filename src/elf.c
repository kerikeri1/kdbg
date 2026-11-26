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
 *
 * Calls to shared library functions (printf, puts...) go through PLT stubs,
 * which have no entry in .symtab. Their names are recovered from the
 * relocations in .rela.plt (see load_plt_symbols).
 */
#define _GNU_SOURCE
#include "elf.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct symbol *symbols;
static int sym_count;
static int sym_cap;

static void add_symbol(const char *name, uint64_t addr, uint64_t size, int is_func)
{
    if (sym_count == sym_cap) {
        sym_cap = sym_cap ? sym_cap * 2 : 64;
        symbols = realloc(symbols, sym_cap * sizeof *symbols);
    }
    symbols[sym_count++] = (struct symbol){
        .name = strdup(name), .addr = addr, .size = size, .is_func = is_func,
    };
}

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

/*
 * Give a name to every PLT stub (printf@plt, puts@plt...).
 *
 * A call to printf in the program is really "call printf@plt". Each PLT
 * stub is 16 bytes and contains an indirect jump through a GOT slot:
 *
 *     printf@plt:  [endbr64]  jmp qword ptr [rip + disp]   ; ff 25 disp32
 *
 * The dynamic linker fills that GOT slot with the real address of printf.
 * Each relocation in .rela.plt says "slot at r_offset belongs to symbol N"
 * (N indexes .dynsym, whose names are in .dynstr). So: decode the jmp in
 * each stub, compute its GOT slot, find the relocation for that slot.
 *
 * Depending on the compiler the stubs are in .plt or in .plt.sec (with
 * CET/IBT enabled), so we scan both: stubs without "ff 25" are skipped.
 */
static void load_plt_symbols(uint8_t *data, Elf64_Ehdr *eh, uint64_t base)
{
    Elf64_Shdr *sh = (Elf64_Shdr *)(data + eh->e_shoff);
    const char *shnames = (const char *)(data + sh[eh->e_shstrndx].sh_offset);

    Elf64_Shdr *rela = NULL;
    for (int i = 0; i < eh->e_shnum; i++)
        if (sh[i].sh_type == SHT_RELA && !strcmp(shnames + sh[i].sh_name, ".rela.plt"))
            rela = &sh[i];
    if (!rela)
        return;  /* statically linked: no PLT */

    Elf64_Rela *rels = (Elf64_Rela *)(data + rela->sh_offset);
    int nrels = rela->sh_size / sizeof(Elf64_Rela);
    Elf64_Shdr *dynsym = &sh[rela->sh_link];
    Elf64_Sym *dsyms = (Elf64_Sym *)(data + dynsym->sh_offset);
    const char *dstr = (const char *)(data + sh[dynsym->sh_link].sh_offset);

    for (int i = 0; i < eh->e_shnum; i++) {
        const char *name = shnames + sh[i].sh_name;
        if (strcmp(name, ".plt") && strcmp(name, ".plt.sec"))
            continue;

        uint8_t *code = data + sh[i].sh_offset;
        for (uint64_t off = 0; off + 16 <= sh[i].sh_size; off += 16) {
            /* look for "jmp [rip + disp32]" (ff 25) in the stub */
            for (int k = 0; k + 6 <= 16; k++) {
                if (code[off + k] != 0xff || code[off + k + 1] != 0x25)
                    continue;
                int32_t disp;
                memcpy(&disp, code + off + k + 2, 4);
                /* rip-relative: from the end of the 6-byte jmp */
                uint64_t got = sh[i].sh_addr + off + k + 6 + disp;

                for (int r = 0; r < nrels; r++) {
                    if (rels[r].r_offset != got)
                        continue;
                    char plt_name[256];
                    snprintf(plt_name, sizeof plt_name, "%s@plt",
                             dstr + dsyms[ELF64_R_SYM(rels[r].r_info)].st_name);
                    add_symbol(plt_name, base + sh[i].sh_addr + off, 16, 1);
                    break;
                }
                break;
            }
        }
    }
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

    Elf64_Shdr *sh = (Elf64_Shdr *)(data + eh->e_shoff);
    sym_count = 0;

    /* 3. Walk the section headers looking for the symbol table */
    Elf64_Shdr *symtab = NULL;
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type == SHT_SYMTAB) {
            symtab = &sh[i];
            break;
        }
    }

    if (!symtab) {
        fprintf(stderr, "%s: no .symtab (binary is stripped?)\n", path);
    } else {
        /* 4. sh_link of the symbol table is the index of its string table */
        Elf64_Shdr *strtab = &sh[symtab->sh_link];
        const char *names = (const char *)(data + strtab->sh_offset);

        Elf64_Sym *syms = (Elf64_Sym *)(data + symtab->sh_offset);
        int n = symtab->sh_size / sizeof(Elf64_Sym);

        /* 5. Keep only defined functions and variables */
        for (int i = 0; i < n; i++) {
            int type = ELF64_ST_TYPE(syms[i].st_info);
            if ((type != STT_FUNC && type != STT_OBJECT) ||
                syms[i].st_shndx == SHN_UNDEF || syms[i].st_value == 0)
                continue;
            add_symbol(names + syms[i].st_name, base + syms[i].st_value,
                       syms[i].st_size, type == STT_FUNC);
        }
    }

    /* 6. PLT stubs: they survive strip, because the dynamic linker needs them */
    load_plt_symbols(data, eh, base);

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
    sym_cap = 0;
}
