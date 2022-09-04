# vim: sts=-1 sw=4 fdm=marker

CFLAGS=-g
LDFLAGS=-rdynamic

all: ftrace

ftrace: ftrace.o debug.o

clean:
	rm ftrace *.o
