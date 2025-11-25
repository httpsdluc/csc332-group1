# Makefile for timedexec

CC = gcc
CFLAGS = -Wall -Wextra -g -std=c99
TARGET = timedexec

all: $(TARGET)

$(TARGET): timedexec.c
	$(CC) $(CFLAGS) -o $(TARGET) timedexec.c

clean:
	rm -f $(TARGET)

test: $(TARGET)
	chmod +x test_timedexec.sh
	./test_timedexec.sh

.PHONY: all clean test
