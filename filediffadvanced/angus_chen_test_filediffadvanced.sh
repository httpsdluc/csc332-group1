#!/bin/bash

# Test script for angus_chen_filediffadvanced
#
# This script runs 15 comprehensive test cases separated into four categories.
# The tests cover overall functionality, error handling, and edge cases:
#   - Tests 1–7: verify core functionality, including text comparison, binary mode,
#     the stats flag, and writing output to a file.
#   - Tests 8–11: validate error handling (missing arguments, bad file paths,
#     and conflicting flags) and ensure they return proper error codes.
#   - Tests 12–14: check edge cases such as empty files and files with different
#     line counts.
#   - Test 15: verifies the help system (-h flag) displays usage information.

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
TEST_DIR="test_files"

echo "=========================================="
echo "Testing angus_chen_filediffadvanced"
echo "=========================================="
echo ""

# Create test directory
mkdir -p "$TEST_DIR"
cd "$TEST_DIR" || exit 1

# Compile the program first
echo -e "${YELLOW}Compiling angus_chen_filediffadvanced...${NC}"
gcc -Wall -Wextra -o ../angus_chen_filediffadvanced ../angus_chen_filediffadvanced.c
if [ $? -ne 0 ]; then
    echo -e "${RED}COMPILATION FAILED${NC}"
    exit 1
fi
echo -e "${GREEN}Compilation successful${NC}"
echo ""

# ========================================
# TEST 1: Identical text files
# ========================================
echo "Test 1: Identical text files"
echo "Hello World" > test1a.txt
echo "Hello World" > test1b.txt
../angus_chen_filediffadvanced test1a.txt test1b.txt > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ PASS${NC}: Identical files return exit code 0"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Identical files should return exit code 0"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 2: Different text files
# ========================================
echo "Test 2: Different text files"
echo "Hello World" > test2a.txt
echo "Goodbye World" > test2b.txt
../angus_chen_filediffadvanced test2a.txt test2b.txt > test2_output.txt 2>&1
if [ $? -eq 1 ] && grep -q "Line 1 differs" test2_output.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Different files return exit code 1 and show differences"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Different files should return exit code 1"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 3: Binary mode comparison
# ========================================
echo "Test 3: Binary mode comparison"
printf "\x00\x01\x02\x03" > test3a.bin
printf "\x00\xFF\x02\x03" > test3b.bin
../angus_chen_filediffadvanced -b test3a.bin test3b.bin > test3_output.txt 2>&1
if grep -q "Offset 0x" test3_output.txt && grep -q "BINARY COMPARISON" test3_output.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Binary mode shows hex offsets"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Binary mode should show offset differences"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 4: Text mode flag
# ========================================
echo "Test 4: Force text mode"
echo "line1" > test4a.txt
echo "line2" > test4b.txt
../angus_chen_filediffadvanced -t test4a.txt test4b.txt > test4_output.txt 2>&1
if grep -q "TEXT COMPARISON" test4_output.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Text mode flag works"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: -t flag should force text mode"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 5: Performance statistics
# ========================================
echo "Test 5: Performance statistics flag"
echo "test" > test5a.txt
echo "test" > test5b.txt
../angus_chen_filediffadvanced -s test5a.txt test5b.txt > test5_output.txt 2>&1
if grep -q "Execution time" test5_output.txt && grep -q "Throughput" test5_output.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Stats flag displays performance metrics"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: -s flag should show performance statistics"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 6: Output to file
# ========================================
echo "Test 6: Output to file"
echo "test1" > test6a.txt
echo "test2" > test6b.txt
../angus_chen_filediffadvanced -o test6_results.txt test6a.txt test6b.txt
if [ -f test6_results.txt ] && [ -s test6_results.txt ]; then
    echo -e "${GREEN}✓ PASS${NC}: Output file created successfully"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Output file not created"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 7: Combined flags
# ========================================
echo "Test 7: Combined flags (-t -s)"
echo "hello" > test7a.txt
echo "world" > test7b.txt
../angus_chen_filediffadvanced -t -s test7a.txt test7b.txt > test7_output.txt 2>&1
if grep -q "TEXT COMPARISON" test7_output.txt && grep -q "Execution time" test7_output.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Multiple flags work together"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Combined flags should work"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 8: Missing arguments
# ========================================
echo "Test 8: Error handling - missing arguments"
../angus_chen_filediffadvanced > test8_output.txt 2>&1
if [ $? -eq 2 ] && grep -q "Error" test8_output.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Missing arguments error handled"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Should show error for missing arguments"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 9: Only one file argument
# ========================================
echo "Test 9: Error handling - only one file"
../angus_chen_filediffadvanced test1a.txt > test9_output.txt 2>&1
if [ $? -eq 2 ] && grep -q "Error" test9_output.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Single file argument error handled"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Should show error for single file"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 10: Non-existent file
# ========================================
echo "Test 10: Error handling - non-existent file"
../angus_chen_filediffadvanced nonexistent_file.txt test1a.txt > test10_output.txt 2>&1
if [ $? -eq 2 ] && grep -q "Error opening" test10_output.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Non-existent file error handled"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Should show error for non-existent file"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 11: Conflicting flags
# ========================================
echo "Test 11: Error handling - conflicting -t and -b flags"
../angus_chen_filediffadvanced -t -b test1a.txt test1b.txt > test11_output.txt 2>&1
if [ $? -eq 2 ] && grep -q "Cannot specify both" test11_output.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Conflicting flags error handled"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Should error on conflicting -t and -b flags"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 12: Empty files
# ========================================
echo "Test 12: Both files empty"
touch test12a.txt test12b.txt
../angus_chen_filediffadvanced test12a.txt test12b.txt > test12_output.txt 2>&1
if [ $? -eq 0 ] && grep -q "empty" test12_output.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Empty files handled correctly"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Should detect both files are empty"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 13: One empty file
# ========================================
echo "Test 13: One file empty"
echo "content" > test13a.txt
touch test13b.txt
../angus_chen_filediffadvanced test13a.txt test13b.txt > test13_output.txt 2>&1
if [ $? -eq 1 ] && grep -q "One file is empty" test13_output.txt; then
    echo -e "${GREEN}✓ PASS${NC}: One empty file detected"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Should detect one empty file"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 14: Different line counts
# ========================================
echo "Test 14: Files with different line counts"
printf "line1\nline2\nline3\n" > test14a.txt
printf "line1\nline2\n" > test14b.txt
../angus_chen_filediffadvanced test14a.txt test14b.txt > test14_output.txt 2>&1
if grep -q "Lines only in first file" test14_output.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Different line counts handled"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Should show lines only in first file"
    ((FAILED++))
fi
echo ""

# ========================================
# TEST 15: Help flag
# ========================================
echo "Test 15: Help flag"
../angus_chen_filediffadvanced -h > test15_output.txt 2>&1
if [ $? -eq 0 ] && grep -q "Usage" test15_output.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Help flag works"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: -h flag should show help"
    ((FAILED++))
fi
echo ""

# ========================================
# SUMMARY
# ========================================
echo "=========================================="
echo "Test Results Summary:"
echo "=========================================="
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
TOTAL=$((PASSED + FAILED))
PERCENTAGE=$((PASSED * 100 / TOTAL))
echo "Total:  $TOTAL"
echo "Success Rate: $PERCENTAGE%"
echo "=========================================="

# Cleanup
cd ..
# Uncomment to remove test files after running
# rm -rf "$TEST_DIR"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
