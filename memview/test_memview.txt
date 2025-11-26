#!/bin/bash
# Test cases for memview

echo "=== Test 1: Help message ==="
./memview -h

echo ""
echo "=== Test 2: Memory statistics ==="
./memview -s

echo ""
echo "=== Test 3: Memory maps ==="
./memview -m

echo ""
echo "=== Test 4: View another process ==="
./memview 1

echo ""
echo "=== Test 5: Invalid PID (error handling) ==="
./memview 999999

echo ""
echo "=== All tests complete ==="
