#include "ftrace.h"

/*
 * ptrace functions
 */

void set_breakpoint(callstack_t *callstack)
{
    int status;
    long orig = ptrace(PTRACE_PEEKTEXT, global_pid, callstack->calldata[callstack->depth].retaddr);
    long trap;
    
    trap = (orig & ~0xff) | 0xcc;
    if (opts.verbose)
        printf("[+] Setting breakpoint on 0x%lx\n", callstack->calldata[callstack->depth].retaddr);

    ptrace(PTRACE_POKETEXT, global_pid, callstack->calldata[callstack->depth].retaddr, trap);
    callstack->calldata[callstack->depth].breakpoint.orig_code = orig;
    callstack->calldata[callstack->depth].breakpoint.vaddr = callstack->calldata[callstack->depth].retaddr;

}

void remove_breakpoint(callstack_t *callstack)
{
    int status;
    if (opts.verbose)
        printf("[+] Removing breakpoint from 0x%lx\n", callstack->calldata[callstack->depth].retaddr);
    
    ptrace(PTRACE_POKETEXT, global_pid, 
    callstack->calldata[callstack->depth].retaddr, callstack->calldata[callstack->depth].breakpoint.orig_code);
}

/*
 * Simple array implementation of stack
 * to keep track of function depth and return values
 */

void callstack_init(callstack_t *callstack)
{
    callstack->calldata = (calldata_t *)HeapAlloc(sizeof(calldata_t) * CALLSTACK_DEPTH);
    callstack->depth = -1; // 0 is first element

}

void callstack_push(callstack_t *callstack, calldata_t *calldata)
{
    memcpy(&callstack->calldata[++callstack->depth], calldata, sizeof(calldata_t));
    set_breakpoint(callstack);
}

calldata_t * callstack_pop(callstack_t *callstack)
{
    if (callstack->depth == -1) 
        return NULL;
    
    remove_breakpoint(callstack);
    return (&callstack->calldata[callstack->depth--]);
}

/* View the top of the stack without popping */
calldata_t * callstack_peek(callstack_t *callstack)
{
    if (callstack->depth == -1)
        return NULL;
    
    return &callstack->calldata[callstack->depth];

}

struct call_list * add_call_string(struct call_list **head, const char *string)
{
    struct call_list *tmp = (struct call_list *)HeapAlloc(sizeof(struct call_list));
    
    tmp->callstring = (char *)xstrdup(string);
    tmp->next = *head; 
    *head = tmp;
    
    return *head;

}

void clear_call_list(struct call_list **head)
{
    struct call_list *tmp;
    
    if (!head)
        return;

    while (*head != NULL) {
        tmp = (*head)->next;
        free (*head);
        *head = tmp;
    }
}

struct branch_instr * search_branch_instr(uint8_t instr)
{
    int i;
    struct branch_instr *p, *ret;
    
    for (i = 0, p = branch_table; p->mnemonic != NULL; p++, i++) {
        if (instr == p->opcode)
            return p;
    }
    
    return NULL;
}

void print_call_list(struct call_list **head)
{
    if (!head)
        return;
    
    while (*head != NULL) {
        fprintf(stdout, "%s", (*head)->callstring);
        head = &(*head)->next;
    }

}

int pid_read(int pid, void *dst, const void *src, size_t len)
{

    int sz = len / sizeof(void *);
    int rem = len % sizeof(void *);
    unsigned char *s = (unsigned char *)src;
    unsigned char *d = (unsigned char *)dst;
    long word;
    
    while (sz-- != 0) {
        word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
        if (word == -1 && errno) 
            return -1;
     
        *(long *)d = word;
        s += sizeof(long);
        d += sizeof(long);
    }
    
    return 0;
}

/*
 * This function attempts to get an ascii string
 * from a pointer location.
 */
#ifdef __x86_64__
char *getstr(unsigned long addr, int pid)
{    
    int i, j, c;
    uint8_t buf[sizeof(long)];
    char *string = (char *)HeapAlloc(256);
    unsigned long vaddr;
    
    string[0] = '"';
    for (c = 1, i = 0; i < 256; i += sizeof(long)) {
        vaddr = addr + i;

        if (pid_read(pid, buf, (void *)vaddr, sizeof(long)) == -1) {
            fprintf(stderr, "pid_read() failed: %s <0x%lx>\n", strerror(errno), vaddr);
            exit(-1);
        }
 
        for (j = 0; j < sizeof(long); j++) {

            if (buf[j] == '\n') {
                string[c++] = '\\';
                string[c++] = 'n';
                continue;
            }
            if (buf[j] == '\t') {
                string[c++] = '\\';
                string[c++] = 't';
                continue;
            }

            if (buf[j] != '\0' && isascii(buf[j]))
                string[c++] = buf[j];
            else
                goto out;
        }
    }
    
out:
    string[c++] = '"';
    string[c] = '\0';

    return string; 

}
#endif

#ifdef __x86_64__
char *getargs(struct user_regs_struct *reg, int pid, struct address_space *addrspace)
{
    unsigned char buf[12];
    int i, c, in_ptr_range = 0, j;
    char *args[256], *p;
    char tmp[512], *s;
    long val;
    char *string = (char *)HeapAlloc(MAXSTR);
    unsigned int maxstr = MAXSTR;
    unsigned int b;

    
    /* x86_64 supported only at this point--
     * We are essentially parsing this
     * calling convention here:
        mov  %rsp,%rbp
        mov  $0x6,%r9d
        mov  $0x5,%r8d
        mov  $0x4,%ecx
        mov  $0x3,%edx
        mov  $0x2,%esi
        mov  $0x1,%edi
        callq 400144 <func>
    */
    

    for (c = 0, in_ptr_range = 0, i = 0; i < 35; i += 5) {
        
        val = reg->rip - i;
        if (pid_read(pid, buf, (void *)val, 8) == -1) {
            fprintf(stderr, "pid_read() failed [%d]: %s <0x%llx>\n", pid, strerror(errno), reg->rip);
            exit(-1);
        }
        
        in_ptr_range = 0;
        if (buf[0] == 0x48 && buf[1] == 0x89 && buf[2] == 0xe5) // mov %rsp, %rbp
            break;
        switch((unsigned char)buf[0]) {
            case 0xbf:
                if (opts.typeinfo || opts.getstr) {
                    for (j = 0; j < 4; j++) {
                        if (reg->rdi >= addrspace[j].svaddr && reg->rdi <= addrspace[j].evaddr) {
                            in_ptr_range++;
                            switch(j) {
                                case TEXT_SPACE:
                                    if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rdi, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }
                                    sprintf(tmp, "(text_ptr *)0x%llx", reg->rdi);
                                    break;
                                case DATA_SPACE:
                                    if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rdi, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }
                                    sprintf(tmp, "(data_ptr *)0x%llx", reg->rdi);
                                    break;
                                case HEAP_SPACE:
                                    if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rdi, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }

                                    sprintf(tmp, "(heap_ptr *)0x%llx", reg->rdi);
                                    break;
                                case STACK_SPACE:
                                     if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rdi, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }
                                    sprintf(tmp, "(stack_ptr *)0x%llx", reg->rdi);
                                    break;
                            }
                        }
                    }
                    if (!in_ptr_range) {
                        sprintf(tmp, "0x%llx",reg->rdi);
                    }    
                    if (!s)
                        args[c++] = xstrdup(tmp);
                    break;
                }
                sprintf(tmp, "0x%llx", reg->rdi);
                args[c++] = xstrdup(tmp);
                break;
            case 0xbe:
                if (opts.typeinfo) {
                    for (j = 0; j < 4; j++) {
                        if (reg->rsi >= addrspace[j].svaddr && reg->rsi <= addrspace[j].evaddr) {
                            in_ptr_range++;
                            switch(j) {
                                case TEXT_SPACE:
                                    if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rsi, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }

                                    sprintf(tmp, "(text_ptr *)0x%llx", reg->rsi);
                                    break;
                                case DATA_SPACE:
                                     if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rsi, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }

                                    sprintf(tmp, "(data_ptr *)0x%llx", reg->rsi);
                                    break;
                                case HEAP_SPACE:
                                     if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rsi, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }

                                    sprintf(tmp, "(heap_ptr *)0x%llx", reg->rsi);
                                    break;
                                case STACK_SPACE:
                                     if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rsi, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }

                                    sprintf(tmp, "(stack_ptr *)0x%llx", reg->rsi);
                                    break;
                            }
                        }
                    }
                    if (!in_ptr_range) {
                        sprintf(tmp, "0x%llx", reg->rsi);
                    }
                    if (!s)
                        args[c++] = xstrdup(tmp);
                    break;
                }

                sprintf(tmp, "0x%llx", reg->rsi);
                args[c++] = xstrdup(tmp);
                break;
            case 0xba:
                 if (opts.typeinfo) {
                    for (j = 0; j < 4; j++) {
                        if (reg->rdx >= addrspace[j].svaddr && reg->rdx <= addrspace[j].evaddr) {
                            in_ptr_range++;
                            switch(j) {
                                case TEXT_SPACE:
                                    if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rdx, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }

                                    sprintf(tmp, "(text_ptr *)0x%llx", reg->rdx);
                                    break;
                                case DATA_SPACE:
                                    if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rdx, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }
                                    sprintf(tmp, "(data_ptr *)0x%llx", reg->rdx);
                                    break;
                                case HEAP_SPACE:
                                    if (opts.getstr) {               
                                        s = getstr((unsigned long)reg->rdx, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }
                                    sprintf(tmp, "(heap_ptr *)0x%llx", reg->rdx);
                                    break;
                                case STACK_SPACE:
                                    if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rdx, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }
                                    sprintf(tmp, "(stack_ptr *)0x%llx", reg->rdx);
                                    break;
                            }
                        }
                    }
                    if (!in_ptr_range) {
                        sprintf(tmp, "0x%llx", reg->rdx);
                    }
                    if (!s)
                        args[c++] = xstrdup(tmp);
                    break;
                }

                sprintf(tmp, "0x%llx", reg->rdx);
                args[c++] = xstrdup(tmp);
                break;
            case 0xb9:
                if (opts.typeinfo) {
                    for (j = 0; j < 4; j++) {
                        if (reg->rcx >= addrspace[j].svaddr && reg->rcx <= addrspace[j].evaddr) {
                            in_ptr_range++;
                            switch(j) {
                                case TEXT_SPACE:
                                    if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rcx, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }
                                    sprintf(tmp, "(text_ptr *)0x%llx", reg->rcx);
                                    break;
                                case DATA_SPACE:
                                    if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rcx, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }
                                    sprintf(tmp, "(data_ptr *)0x%llx", reg->rcx);
                                    break;
                                case HEAP_SPACE:
                                    if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rcx, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }
                                    sprintf(tmp, "(heap_ptr *)0x%llx", reg->rcx);
                                    break;
                                case STACK_SPACE:
                                    if (opts.getstr) {
                                        s = getstr((unsigned long)reg->rcx, pid);
                                        if (s) {
                                            snprintf(tmp, sizeof(tmp), "%s", s);
                                            args[c++] = xstrdup(tmp);
                                            break;
                                        }
                                    }

                                    sprintf(tmp, "(stack_ptr *)0x%llx", reg->rcx);
                                    break;
                            }
                        }
                    }
                    if (!in_ptr_range) {
                        sprintf(tmp, "0x%llx", reg->rcx);
                    }
                    if (!s)
                        args[c++] = xstrdup(tmp);
                    break;
                }

                sprintf(tmp, "0x%llx", reg->rcx);
                args[c++] = xstrdup(tmp);
                break;
            case 0x41:
                switch((unsigned char)buf[1]) {
                    case 0xb8:
                        if (opts.typeinfo) {
                            for (j = 0; j < 4; j++) {
                                if (reg->r8 >= addrspace[j].svaddr && reg->r8 <= addrspace[j].evaddr) {
                                    in_ptr_range++;
                                    switch(j) {
                                        case TEXT_SPACE:
                                            if (opts.getstr) {
                                                s = getstr((unsigned long)reg->r8, pid);
                                                if (s) {
                                                    snprintf(tmp, sizeof(tmp), "%s", s);
                                                    args[c++] = xstrdup(tmp);
                                                    break;
                                                }
                                            }
                                            sprintf(tmp, "(text_ptr *)0x%llx", reg->r8);
                                            break;
                                        case DATA_SPACE:
                                            if (opts.getstr) {
                                                s = getstr((unsigned long)reg->r8, pid);
                                                if (s) {
                                                    snprintf(tmp, sizeof(tmp), "%s", s);
                                                    args[c++] = xstrdup(tmp);
                                                    break;
                                                }
                                            }
                                            sprintf(tmp, "(data_ptr *)0x%llx", reg->r8);
                                            break;
                                        case HEAP_SPACE:
                                            if (opts.getstr) {
                                                s = getstr((unsigned long)reg->r8, pid);
                                                if (s) {
                                                    snprintf(tmp, sizeof(tmp), "%s", s);
                                                    args[c++] = xstrdup(tmp);
                                                    break;
                                                }
                                            }
                                            sprintf(tmp, "(heap_ptr *)0x%llx", reg->r8);
                                            break;
                                        case STACK_SPACE:
                                            if (opts.getstr) {
                                                s = getstr((unsigned long)reg->r8, pid);
                                                if (s) {
                                                    snprintf(tmp, sizeof(tmp), "%s", s);
                                                    args[c++] = xstrdup(tmp);
                                                    break;
                                                }
                                            }
                                            sprintf(tmp, "(stack_ptr *)0x%llx", reg->r8);
                                            break;
                                    }
                                }
                            }
                            if (!in_ptr_range) {
                                sprintf(tmp, "0x%llx", reg->r8);
                            }
                            if (!s)
                                args[c++] = xstrdup(tmp);
                            break;
                        }
                        
                        sprintf(tmp, "0x%llx", reg->r8);
                        args[c++] = xstrdup(tmp);
                        break;
                    case 0xb9:
                        if (opts.typeinfo) {
                            for (j = 0; j < 4; j++) {
                                if (reg->r9 >= addrspace[j].svaddr && reg->r9 <= addrspace[j].evaddr) {
                                    in_ptr_range++;
                                    switch(j) {
                                        case TEXT_SPACE:
                                            if (opts.getstr) {
                                                s = getstr((unsigned long)reg->r9, pid);
                                                if (s) {
                                                    snprintf(tmp, sizeof(tmp), "%s", s);
                                                    args[c++] = xstrdup(tmp);
                                                    break;
                                                }
                                            }
                                            sprintf(tmp, "(text_ptr *)0x%llx", reg->r9);
                                            break;
                                        case DATA_SPACE:
                                            if (opts.getstr) {
                                                s = getstr((unsigned long)reg->r9, pid);
                                                if (s) {
                                                    snprintf(tmp, sizeof(tmp), "%s", s);
                                                    args[c++] = xstrdup(tmp);
                                                    break;
                                                }
                                            }
                                            sprintf(tmp, "(data_ptr *)0x%llx", reg->r9);
                                            break;
                                        case HEAP_SPACE:
                                             if (opts.getstr) {
                                                s = getstr((unsigned long)reg->r9, pid);
                                                if (s) {
                                                    snprintf(tmp, sizeof(tmp), "%s", s);
                                                    args[c++] = xstrdup(tmp);
                                                    break;
                                                }
                                            }
                                            sprintf(tmp, "(heap_ptr *)0x%llx", reg->r9);
                                            break;
                                        case STACK_SPACE:
                                             if (opts.getstr) {
                                                s = getstr((unsigned long)reg->r9, pid);
                                                if (s) {
                                                    snprintf(tmp, sizeof(tmp), "%s", s);
                                                    args[c++] = xstrdup(tmp);
                                                    break;
                                                }
                                            }
                                            sprintf(tmp, "(stack_ptr *)0x%llx", reg->r9);
                                            break;
                                    }    
                                }
                            }
                            if (!in_ptr_range) {
                                sprintf(tmp, "0x%llx", reg->r9);
                            }
                            if (!s)
                                args[c++] = xstrdup(tmp);
                            break;    
                        }

                        sprintf(tmp, "0x%llx", reg->r9);
                        args[c++] = xstrdup(tmp);
                        break;
                }
        }
    }

    /*
     * XXX pre-allocation for strcpy/strcat, tested with super long function name
     */
    if (c == 0)
        return NULL;
    
    for (b = 0, i = 0; i < c; i++) 
        b += strlen(args[i]) + 1; // len + ','
    if (b > maxstr + 2) { // maxstr + 2 braces
        string = realloc((char *)string, maxstr + (b - (maxstr + 2)) + 1);
        maxstr += (b - maxstr) + 3;
    }
    
    string[0] = '(';
    strcpy((char *)&string[1], args[0]);
    strcat(string, ",");
    
    for (i = 1; i < c; i++) {
        strcat(string, args[i]);
        strcat(string, ",");
    }
        
    if ((p = strrchr(string, ','))) 
        *p = '\0';
    strcat(string, ")");
    return string;

}
#endif

