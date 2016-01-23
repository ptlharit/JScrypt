
CC=g++
CFLAGS=-c -Wall
OBJS=main.o hello.o factorial.o
all: hello

hello: $(OBJS)
	$(CC) $? -o $@

main.o: main.cpp
	g++ -c main.cpp

hello.o: hello.cpp
	g++ -c hello.cpp

factorial.o: factorial.cpp
	g++ -c factorial.cpp

clean:
	rm $(OBJS) hello
