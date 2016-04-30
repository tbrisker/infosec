OBJS = main.o util.o

all: main.o util.o
	gcc -o main -Wall $(OBJS)

main.o:
	gcc -Wall -c main.c

util.o:
	gcc -Wall -c util.c

clean:
	rm *.o main
