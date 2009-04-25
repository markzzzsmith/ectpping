
ectpping : ectpping.c libenetaddr.o libectp.o
	gcc -lpthread -Wall libenetaddr.o libectp.o ectpping.c -o ectpping

libenetaddr.o : libenetaddr.h libenetaddr.c
	gcc -Wall -c libenetaddr.c

libectp.o : libectp.h libectp.c
	gcc -Wall -c libectp.c

clean:
	rm -f ectpping libenetaddr.o libectp.o

