#include "ftrace.h"

/*
 * A couple of commonly used utility
 * functions for mem allocation
 * malloc, strdup wrappers.
 */

void * HeapAlloc(unsigned int len)
{
	uint8_t *mem = malloc(len);
	if (!mem) {
		perror("malloc");
		exit(-1);
	}
	return mem;
}

char * xstrdup(const char *s)
{
	char *p = strdup(s);
	if (p == NULL) {
		perror("strdup");
		exit(-1);
	}
	return p;
}
	
char * xfmtstrdup(char *fmt, ...)
{
	char *s, buf[512];
	va_list va;
        
	va_start (va, fmt);
	vsnprintf (buf, sizeof(buf), fmt, va);
	s = xstrdup(buf);
	
	return s;
}

int distance(unsigned long a, unsigned long b)
{
	return ((a > b) ? (a - b) : (b - a));
}

/*
 * Parse /proc/<pid>/maps to get address space layout
 * of executable text/data, heap, stack.
 */
void get_address_space(struct address_space *addrspace, int pid, char *path)
{
	char tmp[64], buf[256];
        char *p, addrstr[32];
	FILE *fd;
        int i, lc;
	
        snprintf(tmp, 64, "/proc/%d/maps", pid);

        if ((fd = fopen(tmp, "r")) == NULL) {
                fprintf(stderr, "Unable to open %s: %s\n", tmp, strerror(errno));
                exit(-1);
        }
	
        for (lc = 0, p = buf; fgets(buf, sizeof(buf), fd) != NULL; lc++) {
		/*
		 * Get executable text and data
	 	 * segment addresses.
		 */
		/** if ((char *)strchr(buf, '/') && lc == 0) { */
		if ((char *)strchr(buf, '/') && strstr(buf, path) && strstr(buf, "r-xp")) {
			for (i = 0; *p != '-'; i++, p++) 
				addrstr[i] = *p;
			addrstr[i] = '\0';
			addrspace[TEXT_SPACE].svaddr = strtoul(addrstr, NULL, 16);
			for (p = p + 1, i = 0; *p != 0x20; i++, p++)
				addrstr[i] = *p;
			addrstr[i] = '\0';
			addrspace[TEXT_SPACE].evaddr = strtoul(addrstr, NULL, 16);
			addrspace[TEXT_SPACE].size = addrspace[TEXT_SPACE].evaddr - addrspace[TEXT_SPACE].svaddr;
		}
		
		if ((char *)strchr(buf, '/') && strstr(buf, path) && strstr(buf, "rw-p")) {
			for (i = 0, p = buf; *p != '-'; i++, p++)
				addrstr[i] = *p;				
			addrstr[i] = '\0';
			addrspace[DATA_SPACE].svaddr = strtoul(addrstr, NULL, 16);
			for (p = p + 1, i = 0; *p != 0x20; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[DATA_SPACE].evaddr = strtoul(addrstr, NULL, 16);
                        addrspace[DATA_SPACE].size = addrspace[DATA_SPACE].evaddr - addrspace[DATA_SPACE].svaddr;
		}
		/*
		 * Get the heap segment address layout
	 	 */
		if (strstr(buf, "[heap]")) {
			for (i = 0, p = buf; *p != '-'; i++, p++)
				addrstr[i] = *p;
			addrstr[i] = '\0';
			addrspace[HEAP_SPACE].svaddr = strtoul(addrstr, NULL, 16);
			for (p = p + 1, i = 0; *p != 0x20; i++, p++)
				addrstr[i] = *p;
			addrstr[i] = '\0';
			addrspace[HEAP_SPACE].evaddr = strtoul(addrstr, NULL, 16);
			addrspace[HEAP_SPACE].size = addrspace[HEAP_SPACE].evaddr - addrspace[DATA_SPACE].svaddr;
		}
		/*
		 * Get the stack segment layout
		 */
		if (strstr(buf, "[stack]")) {
			 for (i = 0, p = buf; *p != '-'; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[STACK_SPACE].svaddr = strtoul(addrstr, NULL, 16);
                        for (p = p + 1, i = 0; *p != 0x20; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[STACK_SPACE].evaddr = strtoul(addrstr, NULL, 16);
                        addrspace[STACK_SPACE].size = addrspace[STACK_SPACE].evaddr - addrspace[STACK_SPACE].svaddr;
                }
	 }
}

char * get_path(int pid)
{
	char tmp[64], buf[1024];
	char path[256], *ret, *p;
	FILE *fd;
	int i;
	
	snprintf(tmp, 64, "/proc/%d/maps", pid);
	
	if ((fd = fopen(tmp, "r")) == NULL) {
		fprintf(stderr, "Unable to open %s: %s\n", tmp, strerror(errno));
		exit(-1);
	}
	
	if (fread(buf,1, sizeof(buf), fd) == NULL){
		fprintf(stderr, "error read file %s\n", tmp);
		return NULL;
	}
	p = strchr(buf, '/');
	if (!p){
		fprintf(stderr, "/ not found in %s\n", tmp);
		fprintf(stderr, "buf %s\n", buf);
		return NULL;
	}
	for (i = 0; *p != '\n' && *p != '\0'; p++, i++)
		path[i] = *p;
	path[i] = '\0';
	ret = (char *)HeapAlloc(i + 1);
	strcpy(ret, path);
	if (strstr(ret, ".so")) {
		fprintf(stderr, "Process ID: %d appears to be a shared library; file must be an executable. (path: %s)\n",pid, ret);
		exit(-1);
	}
	return ret;
}

int validate_em_type(char *path)
{
	int fd;
	uint8_t *mem, *p;
	unsigned int value;
	Elf64_Ehdr *ehdr64;
	Elf32_Ehdr *ehdr32;

	if ((fd = open(path, O_RDONLY)) < 0) {
		fprintf(stderr, "Could not open %s: %s\n", path, strerror(errno));
		print_trace();
		exit(-1);
	}
	
	mem = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	
	switch (opts.arch) {
		case 32:
			ehdr32 = (Elf32_Ehdr *)mem;
			if (ehdr32->e_machine != EM_386)
				return 0;
			break;
		case 64:
			ehdr64 = (Elf64_Ehdr *)mem;
			if (ehdr64->e_machine != EM_X86_64 && ehdr64->e_machine != EM_IA_64)
				return 0;
			break;
	}
	return 1;
}

