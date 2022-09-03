# vim: sts=-1 sw=4 fdm=marker

LDFLAGS=-g -rdynamic

all: ftrace

ftrace: ftrace.o debug.o

clean:
	rm ftrace
