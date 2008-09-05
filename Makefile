
etherping : etherping.c libenetaddr.o
	gcc -lpthread -Wall libenetaddr.o etherping.c -o etherping

libenetaddr.o : libenetaddr.h libenetaddr.c
	gcc -Wall -c libenetaddr.c

libectp.o : ectp.h libectp.h libectp.c
	gcc -Wall -c libectp.c

clean:
	rm -f etherping libenetaddr.o

