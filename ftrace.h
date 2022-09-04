/*
 * ftrace (Function trace) local execution tracing 
 * <Ryan.Oneill@LeviathanSecurity.com>
 */

#ifndef FTRACE_H
#define FTRACE_H

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/reg.h>
#include <stdarg.h>

/*
 * For our color coding output
 */
#define WHITE "\x1B[37m"
#define RED  "\x1B[31m"
#define GREEN  "\x1B[32m"
#define YELLOW  "\x1B[33m"
#define DEFAULT_COLOR  "\x1B[0m"

#define MAX_SYMS 8192 * 2

/*
 * On 32bit systems should be set:
 * export FTRACE_ARCH=32
 */
#define FTRACE_ENV "FTRACE_ARCH"

#define MAX_ADDR_SPACE 256 
#define MAXSTR 512

#define TEXT_SPACE  0
#define DATA_SPACE  1
#define STACK_SPACE 2
#define HEAP_SPACE  3

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
struct elf_section_range {
	char *sh_name;
	unsigned long sh_addr;
	unsigned int sh_size;
};

struct elf64 {
	Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr *shdr;
        Elf64_Sym  *sym;
        Elf64_Dyn  *dyn;

	char *StringTable;
	char *SymStringTable;
};

struct elf32 {
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	Elf32_Shdr *shdr;
	Elf32_Sym  *sym;
	Elf32_Dyn  *dyn;
	
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
	//	unsigned int depth;
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

void print_trace(void);
void set_breakpoint(callstack_t *callstack);
void remove_breakpoint(callstack_t *callstack);
void callstack_init(callstack_t *callstack);
void callstack_push(callstack_t *callstack, calldata_t *calldata);
calldata_t * callstack_pop(callstack_t *callstack);
calldata_t * callstack_peek(callstack_t *callstack);
struct call_list * add_call_string(struct call_list **head, const char *string);
void clear_call_list(struct call_list **head);
struct branch_instr * search_branch_instr(uint8_t instr);
void print_call_list(struct call_list **head);
void * HeapAlloc(unsigned int len);
char * xstrdup(const char *s);
char * xfmtstrdup(char *fmt, ...);
int pid_read(int pid, void *dst, const void *src, size_t len);
int BuildSyms(struct handle *h);
void locate_dynamic_segment(struct handle *h);
uint8_t *get_section_data(struct handle *h, const char *section_name);
char *get_dt_strtab_name(struct handle *h, int xset);
void parse_dynamic_dt_needed(struct handle *h);
char *getstr(unsigned long addr, int pid);
char *getargs(struct user_regs_struct *reg, int pid, struct address_space *addrspace);
int distance(unsigned long a, unsigned long b);
void examine_process(struct handle *h);
void MapElf32(struct handle *h);
void get_address_space(struct address_space *addrspace, int pid, char *path);
char * get_path(int pid);
int validate_em_type(char *path);
void load_elf_section_range(struct handle *h);
char * get_section_by_range(struct handle *h, unsigned long vaddr);
void MapElf64(struct handle *h);
void sighandle(int sig);

extern struct branch_instr branch_table[64];

struct opts {
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
};

extern struct opts opts;

extern int global_pid;
#endif
