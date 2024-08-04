CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -g

TARGET = send_server

all: $(TARGET)

$(TARGET): server.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
