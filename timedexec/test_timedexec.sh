#!/bin/bash
#
# test_timedexec.sh - Comprehensive test suite for timedexec
# 
# WHAT THIS DOES:
# Tests all features of timedexec to make sure it works correctly

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Function to print test header
print_test() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}TEST: $1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Function to check test result
check_result() {
    if [ $? -eq $1 ]; then
        echo -e "${GREEN}✓ PASS${NC}: $2"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: $2"
        ((TESTS_FAILED++))
    fi
}

# Make sure timedexec is compiled
if [ ! -f ./timedexec ]; then
    echo "Compiling timedexec..."
    make
fi

echo "Starting timedexec test suite..."

# TEST 1: Normal execution (should succeed)
print_test "Normal Execution"
./timedexec echo "Hello, World!"
check_result 0 "Program should execute normally"

# TEST 2: Time limit exceeded
print_test "Time Limit"
./timedexec -t 2 sleep 10
check_result 124 "Should timeout after 2 seconds"

# TEST 3: Normal completion within time limit
print_test "Complete Within Time Limit"
./timedexec -t 5 sleep 1
check_result 0 "Should complete normally within time limit"

# TEST 4: Verbose mode
print_test "Verbose Mode"
./timedexec -v -t 3 echo "Testing verbose"
check_result 0 "Verbose mode should work"

# TEST 5: Invalid command
print_test "Invalid Command"
./timedexec nonexistent_command 2>/dev/null
check_result 1 "Should fail for nonexistent command"

# TEST 6: No command specified
print_test "No Command"
./timedexec 2>/dev/null
check_result 1 "Should fail when no command specified"

# TEST 7: Help option
print_test "Help Option"
./timedexec -h 2>&1 | grep -q "Usage"
check_result 0 "Help should display usage information"

# TEST 8: Command with arguments
print_test "Command with Arguments"
./timedexec ls -la /tmp > /dev/null
check_result 0 "Should handle commands with arguments"

# TEST 9: Multiple limits
print_test "Multiple Limits"
./timedexec -t 5 -m 100 -v echo "Multiple limits"
check_result 0 "Should accept multiple limit flags"

# Create a memory-hungry program for memory testing
cat > /tmp/memory_hog.c << 'EOF'
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main() {
    // Allocate 200MB of memory
    for (int i = 0; i < 200; i++) {
        char *mem = malloc(1024 * 1024);  // 1 MB
        memset(mem, 0, 1024 * 1024);      // Actually use it
        sleep(1);
    }
    return 0;
}
EOF

# Compile memory hog if gcc is available
if command -v gcc &> /dev/null; then
    gcc -o /tmp/memory_hog /tmp/memory_hog.c 2>/dev/null
    
    if [ -f /tmp/memory_hog ]; then
        # TEST 10: Memory limit
        print_test "Memory Limit"
        ./timedexec -m 50 /tmp/memory_hog
        check_result 125 "Should terminate when memory limit exceeded"
    fi
fi

# Create a CPU-intensive program
cat > /tmp/cpu_hog.c << 'EOF'
#include <stdio.h>
int main() {
    volatile long long counter = 0;
    for (long long i = 0; i < 10000000000LL; i++) {
        counter++;
    }
    printf("%lld\n", counter);
    return 0;
}
EOF

# Compile CPU hog if gcc is available
if command -v gcc &> /dev/null; then
    gcc -o /tmp/cpu_hog /tmp/cpu_hog.c 2>/dev/null
    
    if [ -f /tmp/cpu_hog ]; then
        # TEST 11: CPU limit with timeout
        print_test "CPU Intensive Program with Time Limit"
        ./timedexec -t 3 -v /tmp/cpu_hog
        check_result 124 "Should timeout CPU-intensive program"
    fi
fi

# Print summary
echo ""
echo "========================================"
echo "TEST SUMMARY"
echo "========================================"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo "Total: $((TESTS_PASSED + TESTS_FAILED))"
echo "========================================"

# Clean up
rm -f /tmp/memory_hog.c /tmp/memory_hog /tmp/cpu_hog.c /tmp/cpu_hog

# Exit with failure if any tests failed
if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi