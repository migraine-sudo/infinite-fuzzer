ifeq ($(shell uname),Darwin)
# Customized for MACOS(x86)
CC = $(shell whereis clang)
CXX = $(shell whereis clang++)
CFLAGS = -O2 --std=c++11
INCLUDE = -I include/ -I src/
LIB = lib/Darwin/libunicorn.a
LDFLAGS = $(INCLUDE) $(LIB) 
FUZZER = -fsanitize=fuzzer#,address
else
# Customized for Linux
CC = clang
CXX = clang++
CFLAGS = -O2 --std=c++11 -lpthread
INCLUDE = -I include/ -I src/
#LIB = lib/Linux/libunicorn.a
LIB = bin/libunicorn.so
LDFLAGS = $(INCLUDE) $(LIB) -Wl,-rpath=$(shell pwd)/bin
FUZZER = -fsanitize=fuzzer#,address
endif

all: amd64_arg_check demo 
vuln: vuln.cc # 警告，重新编译会导致测试目标代码段偏移，导致example演示失败
	$(CXX) vuln.cc -shared -fPIC -o vuln.so 
#demo-unicorn: demo-unicorn.cc
#	$(CXX) $(CFLAGS) $(LDFLAGS) demo-unicorn.cc -o demo
demo: demo.cc
	$(CXX) $(CFLAGS) $(LDFLAGS) $(FUZZER) demo.cc -o myfuzzer
task1: example/task1.cc
	$(CXX) $(CFLAGS) $(LDFLAGS) example/task1.cc -o task1
task2: example/task2.cc
	$(CXX) $(CFLAGS) $(LDFLAGS) example/task2.cc -o task2 
fuzzer-unicorn: example/fuzzer-unicorn.cc
	$(CXX) $(CFLAGS) $(LDFLAGS) $(FUZZER) example/fuzzer-unicorn.cc -o fuzzer-unicorn
amd64_arg_check: debug/amd64_arg_check.cc
	$(CXX) $(CFLAGS) $(LDFLAGS) $(FUZZER) debug/amd64_arg_check.cc -o amd64_arg_check -D __DEBUG__
clean:
	rm -rf *.o crash-* demo myfuzzer task1 task2 fuzzer-unicorn  amd64_arg_check 
#all: test
#%: %.c
#    $(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@