cc = gcc
CFLAGS = -Wall -Wextra
SRCS = buffer.c client.c helpers.c requests.c

client: $(SRCS)
	$(cc) $(CFLAGS) -o client $(SRCS)

run: client
	./client

clean:
	rm -f *.o client