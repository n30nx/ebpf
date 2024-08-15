CL=clang
CC=gcc

KOPTIONS=-O2 -g -c -target bpf -Wall -Wextra
OPTIONS=-lbpf -lelf -Wall -Wextra -Wall -Wextra
INCLUDE=./include/userspace
OPTS=-fsanitize=address -g -c -I $(INCLUDE)

build: build_kernelspace

build_userspace: clean
	mkdir build
	$(CC) src/userspace/filter.c -o build/filter.o $(OPTS)
	$(CC) src/userspace/json.c -o build/json.o $(OPTS)
	$(CC) src/common/common.c -o build/common.o $(OPTS)
	$(CC) main.c -o build/main.o -pthread $(OPTS)
	$(CC) $(OPTIONS) -o loader build/*.o -fsanitize=address -g -pthread

build_kernelspace: build_userspace
	$(CL) $(KOPTIONS) src/kernelspace/open.c -o open.o
	$(CL) $(KOPTIONS) src/kernelspace/execve.c -o execve.o
	$(CL) $(KOPTIONS) src/kernelspace/openat.c -o openat.o
	$(CL) $(KOPTIONS) src/kernelspace/openat2.c -o openat2.o

clean:
	rm -rf build/
	rm -rf loader
	rm -rf *.o
