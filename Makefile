
etherping : etherping.c libenetaddr.o
	gcc -lpthread -Wall libenetaddr.o etherping.c -o etherping

libenetaddr.o : libenetaddr.h libenetaddr.c
	gcc -Wall -c libenetaddr.c

clean:
	rm -f etherping

