// vim: sts=-1 sw=4 fdm=marker

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/reg.h>
#include <sys/mman.h>

#include <elf.h>

/*
 * For our color coding output
 */
#define WHITE "\x1B[37m"
#define RED    "\x1B[31m"
#define GREEN    "\x1B[32m"
#define YELLOW    "\x1B[33m"
#define DEFAULT_COLOR    "\x1B[0m"

#define MAX_SYMS 8192 * 2

/*
 * On 32bit systems should be set:
 * export FTRACE_ARCH=32
 */
#define FTRACE_ENV "FTRACE_ARCH"

#define MAX_ADDR_SPACE 256
#define MAXSTR 512

#define TEXT_SPACE    0
#define DATA_SPACE    1
#define STACK_SPACE 2
#define HEAP_SPACE    3

#define CALLSTACK_DEPTH 0xf4240


struct branch_instr {
    char *mnemonic;
    uint8_t opcode;
};


#define BRANCH_INSTR_LEN_MAX 5

/*
 * Table for (non-call) branch instructions used
 * in our control flow analysis.
 */
struct branch_instr branch_table[64] = {
    {"jo",    0x70},
    {"jno", 0x71},    {"jb", 0x72},    {"jnae", 0x72},    {"jc", 0x72},    {"jnb", 0x73},
    {"jae", 0x73},    {"jnc", 0x73}, {"jz", 0x74},        {"je", 0x74},    {"jnz", 0x75},
    {"jne", 0x75},    {"jbe", 0x76}, {"jna", 0x76},     {"jnbe", 0x77}, {"ja", 0x77},
    {"js",    0x78},    {"jns", 0x79}, {"jp", 0x7a},    {"jpe", 0x7a}, {"jnp", 0x7b},
    {"jpo", 0x7b},    {"jl", 0x7c},    {"jnge", 0x7c},    {"jnl", 0x7d}, {"jge", 0x7d},
    {"jle", 0x7e},    {"jng", 0x7e}, {"jnle", 0x7f},    {"jg", 0x7f},    {"jmp", 0xeb},
    {"jmp", 0xe9},    {"jmpf", 0xea}, {NULL, 0}
};

struct elf_section_range {
    char *sh_name;
    unsigned long sh_addr;
    unsigned int sh_size;
};

extern struct {
    int stripped;
    int callsite;
    int showret;
    int attach;
    int verbose;
    int elfinfo;
    int typeinfo; //imm vs. ptr
    int getstr;
    int arch;
    int cflow;
} opts;

struct elf64 {
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    Elf64_Sym    *sym;
    Elf64_Dyn    *dyn;

    char *StringTable;
    char *SymStringTable;
};

struct elf32 {
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    Elf32_Shdr *shdr;
    Elf32_Sym    *sym;
    Elf32_Dyn    *dyn;

    char *StringTable;
    char *SymStringTable;

};

struct address_space {
    unsigned long svaddr;
    unsigned long evaddr;
    unsigned int size;
    int count;
};

struct syms {
    char *name;
    unsigned long value;
};

typedef struct breakpoint {
    unsigned long vaddr;
    long orig_code;
} breakpoint_t;

typedef struct calldata {
    char *symname;
    char *string;
    unsigned long vaddr;
    unsigned long retaddr;
    //    unsigned int depth;
    breakpoint_t breakpoint;
} calldata_t;

typedef struct callstack {
    calldata_t *calldata;
    unsigned int depth;
} callstack_t;

struct call_list {
    char *callstring;
    struct call_list *next;
};

#define MAX_SHDRS 256

struct handle {
    char *path;
    char **args;
    uint8_t *map;
    struct elf32 *elf32;
    struct elf64 *elf64;
    struct elf_section_range sh_range[MAX_SHDRS];
    struct syms lsyms[MAX_SYMS]; //local syms
    struct syms dsyms[MAX_SYMS]; //dynamic syms
    char *libnames[256];
    int lsc; //lsyms count
    int dsc; // dsyms count
    int lnc; //libnames count
    int shdr_count;
    int pid;
};

int global_pid;

void load_elf_section_range(struct handle *);
void get_address_space(struct address_space *, int, char *);
void MapElf32(struct handle *);
void MapElf64(struct handle *);
void *HeapAlloc(unsigned int);
char *xstrdup(const char *);
char *get_section_by_range(struct handle *, unsigned long);

