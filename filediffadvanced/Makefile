# Makefile for filediffadvanced

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99
LDFLAGS = 

# Target executable
TARGET = filediffadvanced

# Source files
SRC = filediffadvanced.c

# Object files
OBJ = $(SRC:.c=.o)

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS)
	@echo "Build successful! Run with: ./$(TARGET) file1 file2"

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Run tests
test: $(TARGET)
	@echo "Running test suite..."
	@chmod +x test_filediffadvanced.sh
	@./test_filediffadvanced.sh

# Clean build artifacts
clean:
	rm -f $(OBJ) $(TARGET)
	rm -rf test_files
	@echo "Cleaned build artifacts"

# Install (copy to /usr/local/bin - requires sudo)
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod 755 /usr/local/bin/$(TARGET)
	@echo "Installed to /usr/local/bin/$(TARGET)"

# Uninstall
uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstalled $(TARGET)"

# Help
help:
	@echo "Makefile for filediffadvanced"
	@echo ""
	@echo "Usage:"
	@echo "  make          - Build the program"
	@echo "  make test     - Build and run test suite"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make install  - Install to /usr/local/bin (requires sudo)"
	@echo "  make uninstall- Remove from /usr/local/bin (requires sudo)"
	@echo "  make help     - Show this help message"

.PHONY: all test clean install uninstall help