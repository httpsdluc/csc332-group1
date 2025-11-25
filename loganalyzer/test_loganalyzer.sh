set -e

echo "== Building =="
make

echo
echo "== Test 1: basic analysis =="

cat > test1.log << 'EOF'
2024-01-01 10:00:00 [INFO] Service started
2024-01-01 10:01:00 [WARN] High memory usage
2024-01-01 10:02:00 [ERROR] Failed to open file
2024-01-01 10:03:00 [INFO] Request handled successfully
EOF

./loganalyzer -f test1.log

echo
echo "== Test 2: keyword = ERROR =="

./loganalyzer -f test1.log -k ERROR

echo
echo "== Test 3: log level counts =="

./loganalyzer -f test1.log -l

echo
echo "== Test 4: keyword + levels =="

./loganalyzer -f test1.log -k INFO -l

echo
echo "== Test 5: missing file (error handling) =="

./loganalyzer -f does_not_exist.log || echo "Expected failure: missing file"

echo
echo "All tests completed."
