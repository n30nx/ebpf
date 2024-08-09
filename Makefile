CL=clang
CC=gcc

KOPTIONS=-O2 -g -c -target bpf
OPTIONS=-lbpf -lelf
INCLUDE=./include/userspace

build: build_kernelspace

build_userspace: clean
	mkdir build
	$(CC) -c -I $(INCLUDE) src/userspace/filter.c -o build/filter.o -fsanitize=address -g
	$(CC) -c -I $(INCLUDE) src/userspace/json.c -o build/json.o -fsanitize=address -g
	$(CC) -c -I $(INCLUDE) src/common/common.c -o build/common.o -fsanitize=address -g
	$(CC) -c -I $(INCLUDE) main.c -o build/main.o -fsanitize=address -g
	$(CC) $(OPTIONS) -o loader build/*.o -fsanitize=address -g

build_kernelspace: build_userspace
	$(CL) $(KOPTIONS) src/kernelspace/execve.c -o execve.o

clean:
	rm -rf build/
	rm -rf execve.o
