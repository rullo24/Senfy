CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -g

TARGET = recv_client

all: $(TARGET)

$(TARGET): client.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)