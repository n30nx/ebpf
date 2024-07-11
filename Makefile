build:
	clang -O2 -target bpf -c src/execve.c -o execve.o
	gcc main.c -o loader -lbpf -lelf
