DISPATCHER_NAME := dispatcher
COMPILER=g++

all: build

build: $(DISPATCHER_NAME)

$(DISPATCHER_NAME): dispatcher.o
	$(COMPILER) -o $(DISPATCHER_NAME) dispatcher.o -lpthread

dispatcher.o: dispatcher.cpp
	$(COMPILER) -c dispatcher.cpp -o dispatcher.o

run-dispatcher:
	./$(DISPATCHER_NAME)

clean:
	rm $(DISPATCHER_NAME) *.o
