#include "ftrace.h"

/*
 * Get global/local and dynamic
 * symbol/function information.
 */
int BuildSyms(struct handle *h)
{
	unsigned int i, j, k;
	char *SymStrTable;
	Elf32_Ehdr *ehdr32;
	Elf32_Shdr *shdr32;
	Elf32_Sym  *symtab32;
	Elf64_Ehdr *ehdr64;
	Elf64_Shdr *shdr64;
	Elf64_Sym  *symtab64;
	int st_type;
	
	h->lsc = 0;
	h->dsc = 0;

	switch(opts.arch) {
		case 32:
			ehdr32 = h->elf32->ehdr;
			shdr32 = h->elf32->shdr;
		
			for (i = 0; i < ehdr32->e_shnum; i++) {
				if (shdr32[i].sh_type == SHT_SYMTAB || shdr32[i].sh_type == SHT_DYNSYM) {
					 
				 	SymStrTable = (char *)&h->map[shdr32[shdr32[i].sh_link].sh_offset]; 
                       			symtab32 = (Elf32_Sym *)&h->map[shdr32[i].sh_offset];
					
                        		for (j = 0; j < shdr32[i].sh_size / sizeof(Elf32_Sym); j++, symtab32++) {
						
						st_type = ELF32_ST_TYPE(symtab32->st_info);
						if (st_type != STT_FUNC)
							continue;

						switch(shdr32[i].sh_type) {
							case SHT_SYMTAB:
								h->lsyms[h->lsc].name = xstrdup(&SymStrTable[symtab32->st_name]);
								h->lsyms[h->lsc].value = symtab32->st_value;
								h->lsc++;
								break;
							case SHT_DYNSYM:
								h->dsyms[h->dsc].name = xstrdup(&SymStrTable[symtab32->st_name]);
								h->lsyms[h->lsc].value = symtab32->st_value;
								h->dsc++;
								break;
						}
                        		}
                		}
			}
			
		        h->elf32->StringTable = (char *)&h->map[shdr32[ehdr32->e_shstrndx].sh_offset];
                        for (i = 0; i < ehdr32->e_shnum; i++) {
                                if (!strcmp(&h->elf32->StringTable[shdr32[i].sh_name], ".plt")) {
                                        for (k = 0, j = 0; j < shdr32[i].sh_size; j += 16) {
                                                if (j >= 16) {
                                                        h->dsyms[k++].value = shdr32[i].sh_addr + j;
                                                }
                                        }
                                        break;
                                }
                        } 
			break;
		case 64:
		    	ehdr64 = h->elf64->ehdr;
                        shdr64 = h->elf64->shdr;
		
                        for (i = 0; i < ehdr64->e_shnum; i++) {
                                if (shdr64[i].sh_type == SHT_SYMTAB || shdr64[i].sh_type == SHT_DYNSYM) {

                                        SymStrTable = (char *)&h->map[shdr64[shdr64[i].sh_link].sh_offset];
                                        symtab64 = (Elf64_Sym *)&h->map[shdr64[i].sh_offset];

                                        for (j = 0; j < shdr64[i].sh_size / sizeof(Elf64_Sym); j++, symtab64++) {
						
					  	st_type = ELF64_ST_TYPE(symtab64->st_info);
						if (st_type != STT_FUNC)
							continue;

                                                switch(shdr64[i].sh_type) {
                                                        case SHT_SYMTAB:
                                                                h->lsyms[h->lsc].name = xstrdup(&SymStrTable[symtab64->st_name]);
                                                                h->lsyms[h->lsc].value = symtab64->st_value;
                                                                h->lsc++;
                                                                break;
                                                        case SHT_DYNSYM:	
                                                                h->dsyms[h->dsc].name = xstrdup(&SymStrTable[symtab64->st_name]);
                                                                h->dsyms[h->dsc].value = symtab64->st_value;
                                                                h->dsc++;
                                                                break;
                                                }
                                        }
                                }
                        }
                        h->elf64->StringTable = (char *)&h->map[shdr64[ehdr64->e_shstrndx].sh_offset];
                        for (i = 0; i < ehdr64->e_shnum; i++) {
                                if (!strcmp(&h->elf64->StringTable[shdr64[i].sh_name], ".plt")) {
                                        for (k = 0, j = 0; j < shdr64[i].sh_size; j += 16) {
                                                if (j >= 16) {
							h->dsyms[k++].value = shdr64[i].sh_addr + j;
                                                }
                                        }
					break;
                                }
                        }
			break;
		}

		return 0;

}

void locate_dynamic_segment(struct handle *h)
{
        int i;
        
	switch (opts.arch) {
		case 32:
        		h->elf32->dyn = NULL;
        		for (i = 0; i < h->elf32->ehdr->e_phnum; i++) {
                		if (h->elf32->phdr[i].p_type == PT_DYNAMIC) {
                        		h->elf32->dyn = (Elf32_Dyn *)&h->map[h->elf32->phdr[i].p_offset];
                        		break;
                		}
       			}				
			break;
		case 64:
		  	h->elf64->dyn = NULL;
                        for (i = 0; i < h->elf64->ehdr->e_phnum; i++) {
                                if (h->elf64->phdr[i].p_type == PT_DYNAMIC) {
                                        h->elf64->dyn = (Elf64_Dyn *)&h->map[h->elf64->phdr[i].p_offset];
                                        break;
                                }
                        } 
			break;
	}

}

uint8_t *get_section_data(struct handle *h, const char *section_name)
{
	
        char *StringTable;
	int i;

	switch (opts.arch) {
		case 32:
			StringTable = h->elf32->StringTable;
			for (i = 0; i < h->elf32->ehdr->e_shnum; i++) {
				if (!strcmp(&StringTable[h->elf32->shdr[i].sh_name], section_name)) {
					return &h->map[h->elf32->shdr[i].sh_offset];
				}
			}
			break;
		case 64:
		 	StringTable = h->elf64->StringTable;
                        for (i = 0; i < h->elf64->ehdr->e_shnum; i++) {
                                if (!strcmp(&StringTable[h->elf64->shdr[i].sh_name], section_name)) {
                                        return &h->map[h->elf64->shdr[i].sh_offset];
                                }
                        }
			break;
	}
	
    return NULL;
}

char *get_dt_strtab_name(struct handle *h, int xset)
{
        static char *dyn_strtbl;

        if (!dyn_strtbl && !(dyn_strtbl = get_section_data(h, ".dynstr"))) 
                printf("[!] Could not locate .dynstr section\n");
  
        return dyn_strtbl + xset;
}

void parse_dynamic_dt_needed(struct handle *h)
{
        char *symstr;
        int i, n_entries;
	Elf32_Dyn *dyn32;
	Elf64_Dyn *dyn64;

        locate_dynamic_segment(h);
        h->lnc = 0;

	switch(opts.arch) {
		case 32:
        		dyn32 = h->elf32->dyn;
        		for (i = 0; dyn32[i].d_tag != DT_NULL; i++) {
                		if (dyn32[i].d_tag == DT_NEEDED) {
                        		symstr = get_dt_strtab_name(h, dyn32[i].d_un.d_val);
                        		h->libnames[h->lnc++] = (char *)xstrdup(symstr);
                		}
      			}
			break;
		case 64:
			dyn64 = h->elf64->dyn;
			for (i = 0; dyn64[i].d_tag != DT_NULL; i++) {
                                if (dyn64[i].d_tag == DT_NEEDED) {
                                        symstr = get_dt_strtab_name(h, dyn64[i].d_un.d_val);
                                        h->libnames[h->lnc++] = (char *)xstrdup(symstr);
                                }
                        }
			break;
		}
}

void MapElf32(struct handle *h)
{
	int fd;
	struct stat st;
	
	if ((fd = open(h->path, O_RDONLY)) < 0) {
		fprintf(stderr, "Unable to open %s: %s\n", h->path, strerror(errno));
		exit(-1);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(-1);
	}

	h->map = (uint8_t *)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (h->map == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}

	h->elf32->ehdr = (Elf32_Ehdr *)h->map;
	h->elf32->shdr = (Elf32_Shdr *)(h->map + h->elf32->ehdr->e_shoff);
	h->elf32->phdr = (Elf32_Phdr *)(h->map + h->elf32->ehdr->e_phoff);
	
	h->elf32->StringTable = (char *)&h->map[h->elf32->shdr[h->elf32->ehdr->e_shstrndx].sh_offset];

 	if (h->elf32->ehdr->e_shnum > 0 && h->elf32->ehdr->e_shstrndx != SHN_UNDEF)
                load_elf_section_range(h);
}

void MapElf64(struct handle *h)
{
	int fd;
        struct stat st;

        if ((fd = open(h->path, O_RDONLY)) < 0) {
                fprintf(stderr, "Unable to open %s: %s\n", h->path, strerror(errno));
                exit(-1);
        }

        if (fstat(fd, &st) < 0) {
                perror("fstat");
                exit(-1);
        }

        h->map = (uint8_t *)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (h->map == MAP_FAILED) {
                perror("mmap");
                exit(-1);
        }

        h->elf64->ehdr = (Elf64_Ehdr *)h->map;
        h->elf64->shdr = (Elf64_Shdr *)(h->map + h->elf64->ehdr->e_shoff);
        h->elf64->phdr = (Elf64_Phdr *)(h->map + h->elf64->ehdr->e_phoff);

        h->elf64->StringTable = (char *)&h->map[h->elf64->shdr[h->elf64->ehdr->e_shstrndx].sh_offset];
	
	if (h->elf64->ehdr->e_shnum > 0 && h->elf64->ehdr->e_shstrndx != SHN_UNDEF)
		load_elf_section_range(h);

}

void load_elf_section_range(struct handle *h)
{
	
	Elf32_Ehdr *ehdr32;
	Elf32_Shdr *shdr32;
	Elf64_Ehdr *ehdr64;
	Elf64_Shdr *shdr64;

	char *StringTable;
	int i;

	h->shdr_count = 0;
	switch(opts.arch) {
		case 32:
			StringTable = h->elf32->StringTable;
			ehdr32 = h->elf32->ehdr;
			shdr32 = h->elf32->shdr;
			
			for (i = 0; i < ehdr32->e_shnum; i++) {
				h->sh_range[i].sh_name = xstrdup(&StringTable[shdr32[i].sh_name]);
				h->sh_range[i].sh_addr = shdr32[i].sh_addr;
				h->sh_range[i].sh_size = shdr32[i].sh_size;
				if (h->shdr_count == MAX_SHDRS)
					break;
				h->shdr_count++;
			}
			break;
		case 64:
		  	StringTable = h->elf64->StringTable;
                        ehdr64 = h->elf64->ehdr;
                        shdr64 = h->elf64->shdr;

                        for (i = 0; i < ehdr64->e_shnum; i++) {
                                h->sh_range[i].sh_name = xstrdup(&StringTable[shdr64[i].sh_name]);
                                h->sh_range[i].sh_addr = shdr64[i].sh_addr;
                                h->sh_range[i].sh_size = shdr64[i].sh_size;
				if (h->shdr_count == MAX_SHDRS)
					break;
				h->shdr_count++;
                        }
                        break;
		
	}
	
}
	
char * get_section_by_range(struct handle *h, unsigned long vaddr)
{
	int i;

	for (i = 0; i < h->shdr_count; i++) {
		if (vaddr >= h->sh_range[i].sh_addr && vaddr <= h->sh_range[i].sh_addr + h->sh_range[i].sh_size)
			return h->sh_range[i].sh_name;
	}
	
	return NULL;
}
	


