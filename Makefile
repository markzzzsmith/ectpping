
etherping: etherping.c
	gcc -lpthread -Wall etherping.c -o etherping

clean:
	rm -f etherping

