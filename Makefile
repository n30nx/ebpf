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
	$(CC) -c -I $(INCLUDE) main.c -o build/main.o -fsanitize=address -g -pthread
	$(CC) $(OPTIONS) -o loader build/*.o -fsanitize=address -g -pthread

build_kernelspace: build_userspace
	$(CL) $(KOPTIONS) src/kernelspace/open.c -o open.o
	$(CL) $(KOPTIONS) src/kernelspace/openat.c -o openat.o
	$(CL) $(KOPTIONS) src/kernelspace/execve.c -o execve.o
	$(CL) $(KOPTIONS) src/kernelspace/openat2.c -o openat2.o
	# $(CL) $(KOPTIONS) src/kernelspace/network.c -o network.o

clean:
	rm -rf build/
	rm -rf loader
	rm -rf *.o
