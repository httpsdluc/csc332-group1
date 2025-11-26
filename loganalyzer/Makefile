# Makefile for loganalyzer command (CSC 332 project)
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -D_GNU_SOURCE -O2
TARGET = loganalyzer

all: $(TARGET)

$(TARGET): loganalyzer.c
	$(CC) $(CFLAGS) -o $(TARGET) loganalyzer.c

clean:
	rm -f $(TARGET) *.o
