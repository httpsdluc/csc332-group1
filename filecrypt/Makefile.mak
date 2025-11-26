# Makefile for filecrypt

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=gnu11 -D_GNU_SOURCE
LDFLAGS = -lssl -lcrypto -lpthread
TARGET = filecrypt
SOURCES = filecrypt.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean install uninstall test debug check valgrind help

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(TARGET) $(OBJECTS)
	rm -f test_*.txt test_*.enc test_*.dec
	rm -f core

install: $(TARGET)
	install -d $(PREFIX)/bin
	install -m 755 $(TARGET) $(PREFIX)/bin

uninstall:
	rm -f $(PREFIX)/bin/$(TARGET)

test: $(TARGET)
	@echo "Running filecrypt test suite..."
	@bash test_filecrypt.sh

# Debug build
debug: CFLAGS += -g -DDEBUG -O0
debug: clean $(TARGET)

# Static analysis
check:
	cppcheck --enable=all --suppress=missingIncludeSystem $(SOURCES)

# Memory leak check
valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET) -e -i test_input.txt -o test_output.enc -p testpass

help:
	@echo "Available targets:"
	@echo "  all       - Build filecrypt (default)"
	@echo "  clean     - Remove built files"
	@echo "  install   - Install to $(PREFIX)"
	@echo "  uninstall - Remove from $(PREFIX)"
	@echo "  test      - Run test suite"
	@echo "  debug     - Build with debug symbols"
	@echo "  check     - Run static analysis"
	@echo "  valgrind  - Run valgrind memory check"