# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -g

# Target names
TARGET_WIN = recv_client.exe
TARGET_LINUX = recv_client

# Source files and target setup based on OS
ifeq ($(OS),Windows_NT)
    SRC = windows_client.c
    TARGET = $(TARGET_WIN)
    LDFLAGS = -lws2_32
    RM = del /Q
else
    SRC = linux_client.c
    TARGET = $(TARGET_LINUX)
    LDFLAGS =
    RM = rm -f
endif

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Clean target
clean:
	$(RM) $(TARGET)
