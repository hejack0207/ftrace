all: ftrace test

ftrace: ftrace.c
	gcc $< -o $@

test: test.c
	gcc $< -o $@
