# vim: sts=-1 sw=4 fdm=marker

CFLAGS=-g
LDFLAGS=-rdynamic

all: ftrace

ftrace: ftrace.o debug.o ptrace.o elf.o utils.o

clean:
	rm ftrace *.o
