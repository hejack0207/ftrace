#include "ftrace.h"

struct branch_instr branch_table[64] = {
			{"jo",  0x70}, 
			{"jno", 0x71},  {"jb", 0x72},  {"jnae", 0x72},  {"jc", 0x72},  {"jnb", 0x73},
			{"jae", 0x73},  {"jnc", 0x73}, {"jz", 0x74},    {"je", 0x74},  {"jnz", 0x75},
			{"jne", 0x75},  {"jbe", 0x76}, {"jna", 0x76},   {"jnbe", 0x77}, {"ja", 0x77},
			{"js",  0x78},  {"jns", 0x79}, {"jp", 0x7a},	{"jpe", 0x7a}, {"jnp", 0x7b},
			{"jpo", 0x7b},  {"jl", 0x7c},  {"jnge", 0x7c},  {"jnl", 0x7d}, {"jge", 0x7d},
			{"jle", 0x7e},  {"jng", 0x7e}, {"jnle", 0x7f},  {"jg", 0x7f},  {"jmp", 0xeb},
			{"jmp", 0xe9},  {"jmpf", 0xea}, {NULL, 0}
		};

struct opts opts;

int global_pid;

/*
 * Our main handler function to parse ELF info
 * read instructions, parse them, and print
 * function calls and stack args.
 */
void examine_process(struct handle *h)
{
	
	int symmatch = 0, cflow_change = 0;
	int i, count, status, in_routine = 0; 
	struct user_regs_struct pt_reg;
	long esp, eax, ebx, edx, ecx, esi, edi, eip;
	uint8_t buf[8];
	unsigned long vaddr;
	unsigned int offset;
	char *argstr = NULL, subname[255], output[512], *sh_src, *sh_dst;
	long ret = 0, event;
	unsigned long retaddr, cip, current_ip;
	struct call_list *call_list = NULL;
	struct branch_instr *branch;
	struct address_space *addrspace = (struct address_space *)HeapAlloc(sizeof(struct address_space) * MAX_ADDR_SPACE); 

	callstack_t callstack;
	calldata_t calldata;
	calldata_t *calldp;

	global_pid = h->pid;
	/*
	 * Allocate ELF structure for
	 * specified Arch, and map in 
	 * the executable file for the
	 * file we are examining.
	 */
	switch(opts.arch) {
		case 32:
			h->elf32 = HeapAlloc(sizeof(struct elf32));
			h->elf64 = NULL;
			MapElf32(h);
			break;
		case 64:
			h->elf64 = HeapAlloc(sizeof(struct elf64));
			h->elf32 = NULL;
			MapElf64(h);
			break;
	}

	/*
	 * Build ELF Symbol information
	 */
	BuildSyms(h);
	
	/* 
	 * Retrieve the program address space layout
	 * to aid in our pointer/type prediction
	 */
	get_address_space((struct address_space *)addrspace, h->pid, h->path);

	if (opts.elfinfo) {
		printf("[+] Printing Symbol Information:\n\n");
		for (i = 0; i < h->lsc; i++) {
			if (h->lsyms[i].name == NULL)
				printf("UNKNOWN: 0x%lx\n", h->lsyms[i].value);
			else
				printf("%s 0x%lx\n", h->lsyms[i].name, h->lsyms[i].value);
		}
		for (i = 0; i < h->dsc; i++) {
			if (h->lsyms[i].name == NULL)
				printf("UNKNOWN: 0x%lx\n", h->lsyms[i].value);
			else
				printf("%s 0x%lx\n", h->dsyms[i].name, h->dsyms[i].value);
		}
		
		printf("\n[+] Printing shared library dependencies:\n\n");
		
		parse_dynamic_dt_needed(h);
		for (i = 0; i < h->lnc; i++) {
			printf("[%d]\t%s\n", i + 1, h->libnames[i]);
		}
	}
	
	if (opts.verbose ) {
	 	printf("[+] Printing the address space layout\n");
                printf("0x%lx-0x%lx %s [text]\n", addrspace[TEXT_SPACE].svaddr, addrspace[TEXT_SPACE].evaddr, h->path);
                printf("0x%lx-0x%lx %s [data]\n", addrspace[DATA_SPACE].svaddr, addrspace[DATA_SPACE].evaddr, h->path);
                printf("0x%lx-0x%lx %s [heap]\n", addrspace[HEAP_SPACE].svaddr, addrspace[HEAP_SPACE].evaddr, h->path);
                printf("0x%lx-0x%lx %s [stack]\n",addrspace[STACK_SPACE].svaddr, addrspace[STACK_SPACE].evaddr, h->path);
	}

	/*
	 * Initiate our call frame stack
	 */
	callstack_init(&callstack);

	printf("\n[+] Function tracing begins here:\n");
        for (;;) {

                ptrace (PTRACE_SINGLESTEP, h->pid, NULL, NULL);
                wait (&status);
                count++;
	//	ptrace(PTRACE_GETREGS, h->pid, NULL, &pt_reg);
					
                if (WIFEXITED (status))
                	break;
		
                ptrace (PTRACE_GETREGS, h->pid, NULL, &pt_reg);
#ifdef __x86_64__
		esp = pt_reg.rsp;
		eip = pt_reg.rip;
		eax = pt_reg.rax;
		ebx = pt_reg.rbx;
		ecx = pt_reg.rcx;
		edx = pt_reg.rdx;
		esi = pt_reg.rsi;
		edi = pt_reg.rdi;
#else
		esp = pt_reg.esp;
		eip = pt_reg.eip;
		eax = pt_reg.eax;
		ebx = pt_reg.ebx;
		ecx = pt_reg.ecx;
		edx = pt_reg.edx;
		esi = pt_reg.esi;
		edi = pt_reg.edi;
#endif
		if (pid_read(h->pid, buf, (void *)eip, 8) < 0) {
			fprintf(stderr, "pid_read() failed: %s <0x%lx>\n", strerror(errno), eip);
			exit(-1);
		}
		
		
		if (opts.cflow) {	
			
			/*
			 * If eip is outside of our binary and in say a shared
			 * object then we don't look at the control flow.
			 */
			if (eip < addrspace[TEXT_SPACE].svaddr || eip > addrspace[TEXT_SPACE].evaddr)
				continue;
			
			if (branch = search_branch_instr(buf[0])) {
				
				ptrace(PTRACE_SINGLESTEP, h->pid, NULL, NULL);
				wait(&status);

				ptrace(PTRACE_GETREGS, h->pid, NULL, &pt_reg);
#ifdef __x86_64__
				current_ip = pt_reg.rip;
#else
				current_ip = pt_reg.eip;
#endif
				
				if (distance(current_ip, eip) > BRANCH_INSTR_LEN_MAX) {
					cflow_change = 1;
					sh_src = get_section_by_range(h, eip);
					sh_dst = get_section_by_range(h, current_ip);
					printf("%s(CONTROL FLOW CHANGE [%s]):%s Jump from %s 0x%lx into %s 0x%lx\n", YELLOW, branch->mnemonic, WHITE,
					!sh_src?"<unknown section>":sh_src, eip, 
					!sh_dst?"<unknown section>":sh_src, current_ip);
				} 

				if (cflow_change) {
					cflow_change = 0;
					continue;
				}

			}
		}

		/*
		 * Did we hit a breakpoint (Return address?)
		 * if so, then we check eax to get the return
		 * value, and pop the call data from the stack,
		 * which will remove the breakpoint as well.
		 */
		if (buf[0] == 0xcc) {
			calldp = callstack_peek(&callstack);
                        if (calldp != NULL) {
                                if (calldp->retaddr == eip) {
					snprintf(output, sizeof(output), "%s(RETURN VALUE) %s%s = %lx\n", RED, WHITE, calldp->string, eax);
					
					/*
					 * Pop call stack and remove the
					 * breakpoint at its return address.
					 */
					fprintf(stdout, "%s", output);
                                        calldp = callstack_pop(&callstack);
					free(calldp->string);
					free(calldp->symname);
				}
			}
		}
		
		
		/*
		 * As we catch each immediate call
		 * instruction, we use callstack_push()
		 * to push the call data onto our stack
		 * and set a breakpoint at the return
		 * address of the function call so that we
		 * can get the retrun value with the code above.
		 */
		if (buf[0] == 0xe8) {
			
			offset = buf[1] + (buf[2] << 8) + (buf[3] << 16) + (buf[4] << 24);
			vaddr = eip + offset + 5; 
			vaddr &= 0xffffffff;

			for (i = 0; i < h->lsc; i++) {
				if (vaddr == h->lsyms[i].value) {
#ifdef __x86_64__
					argstr = getargs(&pt_reg, h->pid, addrspace);
#endif
					if (argstr == NULL)
						printf("%sLOCAL_call@0x%lx:%s%s()\n", GREEN, h->lsyms[i].value,  WHITE, !h->lsyms[i].name?"<unknown>":h->lsyms[i].name);
					else
						printf("%sLOCAL_call@0x%lx:%s%s%s\n", GREEN, h->lsyms[i].value, WHITE,  h->lsyms[i].name, argstr);

					calldata.symname = xstrdup(h->lsyms[i].name);
					calldata.vaddr = h->lsyms[i].value;
					calldata.retaddr = eip + 5;
					if (argstr == NULL) 
						calldata.string = xfmtstrdup("LOCAL_call@0x%lx: %s()", h->lsyms[i].value, !h->lsyms[i].name?"<unknown>":h->lsyms[i].name);
					else
						calldata.string = xfmtstrdup("LOCAL_call@0x%lx: %s%s", h->lsyms[i].value, h->lsyms[i].name, argstr);
					
					if (opts.verbose)
						printf("Return address for %s: 0x%lx\n", calldata.symname, calldata.retaddr);
					callstack_push(&callstack, &calldata);
					symmatch = 1;
				}
				
			}
			for (i = 0; i < h->dsc; i++) {
				if (vaddr == h->dsyms[i].value) {
#ifdef __x86_64__
					argstr = getargs(&pt_reg, h->pid, addrspace);
#endif
					if (argstr == NULL)
                                                printf("%sPLT_call@0x%lx:%s%s()\n", GREEN, h->dsyms[i].value, WHITE, !h->dsyms[i].name?"<unknown>":h->dsyms[i].name);
                                        else
                                                printf("%sPLT_call@0x%lx:%s%s%s\n", GREEN, h->dsyms[i].value, WHITE, h->dsyms[i].name, argstr);



					calldata.symname = xstrdup(h->dsyms[i].name);
                                        calldata.vaddr = h->dsyms[i].value;
                                        calldata.retaddr = eip + 5;
					if (argstr == NULL)
						calldata.string = xfmtstrdup("PLT_call@0x%lx: %s()", h->dsyms[i].value, !h->dsyms[i].name?"<unknown>":h->dsyms[i].name);
					else
						calldata.string = xfmtstrdup("PLT_call@0x%lx: %s%s", h->dsyms[i].value, h->dsyms[i].name, argstr);
					if (opts.verbose)
						printf("Return address for %s: 0x%lx\n", calldata.symname, calldata.retaddr);
                                        callstack_push(&callstack, &calldata);
                                        symmatch = 1;
				}
			}
			
			if (opts.stripped) {
				if (symmatch) {
					symmatch = 0;
				} else {
#ifdef __x86_64__
					argstr = getargs(&pt_reg, h->pid, addrspace);
#endif
					if (argstr == NULL)
						printf("%sLOCAL_call@0x%lx:%ssub_%lx()\n", GREEN, vaddr, WHITE, vaddr);
					else
						printf("%sLOCAL_call@0x%lx:%ssub_%lx%s\n", GREEN, vaddr, WHITE, vaddr, argstr);

					snprintf(subname, sizeof(subname) - 1, "sub_%lx%s", vaddr, argstr == NULL ? "()" : argstr);
					calldata.symname = xstrdup(subname);
                                        calldata.vaddr = vaddr;
                                        calldata.retaddr = eip + 5;
					if (argstr == NULL)
						calldata.string = xfmtstrdup("LOCAL_call@0x%lx: sub_%lx()", vaddr, vaddr);
					else
						calldata.string = xfmtstrdup("LOCAL_call@0x%lx: sub_%lx%s", vaddr, vaddr, argstr);
                                        callstack_push(&callstack, &calldata);
                                        symmatch = 1;

				}
			}

			if (argstr) {
				free(argstr);
				argstr = NULL;
			}

 
		}
		
				
	}

}

	
void sighandle(int sig)
{
	fprintf(stdout, "Caught signal ctrl-C, detaching...\n");
	ptrace(PTRACE_DETACH, global_pid, NULL, NULL);
	exit(0);
}


int main(int argc, char **argv, char **envp)
{
	int opt, i, pid, status;
	struct handle handle;
	char **p, *arch;
	
        struct sigaction act;
        sigset_t set;
        act.sa_handler = sighandle;
        sigemptyset (&act.sa_mask);
        act.sa_flags = 0;
        sigaction (SIGINT, &act, NULL);
        sigemptyset (&set);
        sigaddset (&set, SIGINT);

	if (argc < 2) {
usage:
		printf("Usage: %s [-p <pid>] [-Sstve] <prog>\n", argv[0]);
		printf("[-p] Trace by PID\n");
		printf("[-t] Type detection of function args\n");
		printf("[-s] Print string values\n");
	//	printf("[-r] Show return values\n");
		printf("[-v] Verbose output\n");
		printf("[-e] Misc. ELF info. (Symbols,Dependencies)\n");
		printf("[-S] Show function calls with stripped symbols\n");
		printf("[-C] Complete control flow analysis\n");
		exit(0);
	}
	
	if (argc == 2 && argv[1][0] == '-')
		goto usage;

	memset(&opts, 0, sizeof(opts));
	
	opts.arch = 64; // default
	arch = getenv(FTRACE_ENV);
	if (arch != NULL) {
		switch(atoi(arch)) {
			case 32:
				opts.arch = 32;
				break;
			case 64:
				opts.arch = 64;
				break;
			default:
				fprintf(stderr, "Unknown architecture: %s\n", arch);
				break;
		}
	}
	
	/** if (argv[1][0] != '-') { */
        /**  */
	/**         handle.path = xstrdup(argv[1]); */
	/**         handle.args = (char **)HeapAlloc(sizeof(char *) * argc - 1); */
        /**  */
	/**         for (i = 0, p = &argv[1]; i != argc - 1; p++, i++) { */
	/**                 *(handle.args + i) = xstrdup(*p); */
	/**         } */
	/**         *(handle.args + i) = NULL; */
	/**         skip_getopt = 1; */
        /**  */
	/** } else { */
	/**         handle.path = xstrdup(argv[2]); */
	/**         handle.args = (char **)HeapAlloc(sizeof(char *) * argc - 1); */
        /**  */
	/**         for (i = 0, p = &argv[2]; i != argc - 2; p++, i++) { */
	/**                 *(handle.args + i) = xstrdup(*p); */
	/**         } */
	/**         *(handle.args + i) = NULL; */
	/** } */
        /**  */
        /**  */
	/** if (skip_getopt) */
	/**         goto begin; */

	while ((opt = getopt(argc, argv, "CSrhtvep:s")) != -1) {
		switch(opt) {
			case 'S':
				opts.stripped++;
				break;
			case 'r':
				opts.showret++;
				break;
			case 'v':
				opts.verbose++;
				break;
			case 'e':
				opts.elfinfo++;
				break;
			case 't':
				opts.typeinfo++;
				break;
			case 'p':
				opts.attach++;
				/** printf("-p %d specified, opts.attach=%d\n",atoi(optarg),opts.attach); */
				handle.pid = atoi(optarg);
				break;
			case 's':
				opts.getstr++;
				break;
			case 'C':
				opts.cflow++;
				break;
			case 'h':
				goto usage;
			default:
				printf("Unknown option\n");
				exit(0);
		}
	}

	if (optind <= argc -1){
		handle.path = xstrdup(argv[optind]);
		if (optind + 1 <= argc -1) {
			handle.args = (char **)HeapAlloc(sizeof(char *) * argc -1 - optind);

			for (i = 0, p = &argv[optind+1]; i <= (argc-1) - (optind+1); p++, i++) {
				*(handle.args + i) = xstrdup(*p);
			}
			*(handle.args + i) = NULL;
		}
	}

	
begin:
	if (opts.verbose) {
		switch(opts.arch) {
			case 32:
				printf("[+] 32bit ELF mode enabled!\n");
				break;
			case 64:
				printf("[+] 64bit ELF mode enabled!\n");
				break;
		}
		if (opts.typeinfo) 
			printf("[+] Pointer type prediction enabled\n");
	}
	
	if (opts.arch == 32 && opts.typeinfo) {
		printf("[!] Option -t may not be used on 32bit executables\n");
		exit(0);
	}
	
	if (opts.arch == 32 && opts.getstr) {
		printf("[!] Option -s may not be used on 32bit executables\n");
		exit(0);
	}

	if (opts.getstr && opts.typeinfo) {
		printf("[!] Options -t and -s may not be used together\n");
		exit(0);
	}

	/*
	 * We are not attaching, but rather executing
	 * in this first instance
	 */
	if (!opts.attach) {
		
		if (!validate_em_type(handle.path)) {
			printf("[!] ELF Architecture is set to %d, the target %s is not the same architecture\n", opts.arch, handle.path);
			exit(-1);
		}
	
		if ((pid = fork()) < 0) {
			perror("fork");
			exit(-1);
		}
		
		if (pid == 0) {
			if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
              			perror("PTRACE_TRACEME");
              			exit(-1);
			}
			ptrace(PTRACE_SETOPTIONS, 0, 0, PTRACE_O_TRACEEXIT);
		  	execve(handle.path, handle.args, envp);
			exit(0);
		}
		waitpid(0, &status, WNOHANG);
		handle.pid = pid;
		global_pid = pid;
		examine_process(&handle);
		goto done;
	}

	/*
	 * In this second instance we trace an
	 * existing process id.
	 */
	if (ptrace(PTRACE_ATTACH, handle.pid, NULL, NULL) == -1) {
		perror("PTRACE_ATTACH");
		exit(-1);
	}
	handle.path = get_path(handle.pid);
        if (!validate_em_type(handle.path)) {
        	printf("[!] ELF Architecture is set to %d, the target %s is not the same architecture\n", opts.arch, handle.path);
        	exit(-1);
       	}

	waitpid(handle.pid, &status, WUNTRACED);
	global_pid = handle.pid;
	examine_process(&handle);

	
done:
	printf("%s\n", WHITE);
	ptrace(PTRACE_DETACH, handle.pid, NULL, NULL);
	exit(0);

}
