CC = gcc
CFLAGS = -Wall

all: memhog

memhog: memhog.o
	${CC} ${CFLAGS} -o memhog memhog.o

memhog.o: memhog.c
	${CC} ${CFLAGS} -c memhog.c

clean: 
	rm -f *.o memhog
