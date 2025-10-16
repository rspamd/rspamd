#!/bin/bash
# Check AddressSanitizer logs for memory leaks and errors

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$SCRIPT_DIR/../data"

echo "=== Checking AddressSanitizer logs ==="
echo ""

# Find all ASAN log files
ASAN_LOGS=$(find "$DATA_DIR" -name "asan.log*" 2>/dev/null)

if [ -z "$ASAN_LOGS" ]; then
    echo "No ASAN logs found in $DATA_DIR"
    exit 0
fi

TOTAL_LEAKS=0
TOTAL_ERRORS=0

for log_file in $ASAN_LOGS; do
    echo "Analyzing: $log_file"
    echo "----------------------------------------"

    # Count memory leaks
    LEAKS=$(grep -c "LeakSanitizer" "$log_file" 2>/dev/null || echo "0")
    if [ "$LEAKS" -gt 0 ]; then
        echo "  Memory leaks detected: $LEAKS"
        TOTAL_LEAKS=$((TOTAL_LEAKS + LEAKS))

        # Show leak summary
        grep -A 10 "LeakSanitizer" "$log_file" | head -20
    fi

    # Count other errors
    ERRORS=$(grep -c "ERROR: AddressSanitizer" "$log_file" 2>/dev/null || echo "0")
    if [ "$ERRORS" -gt 0 ]; then
        echo "  AddressSanitizer errors: $ERRORS"
        TOTAL_ERRORS=$((TOTAL_ERRORS + ERRORS))

        # Show error summary
        grep -A 10 "ERROR: AddressSanitizer" "$log_file" | head -20
    fi

    # Check for heap-use-after-free
    UAF=$(grep -c "heap-use-after-free" "$log_file" 2>/dev/null || echo "0")
    if [ "$UAF" -gt 0 ]; then
        echo "  Heap-use-after-free: $UAF"
    fi

    # Check for heap-buffer-overflow
    OVERFLOW=$(grep -c "heap-buffer-overflow" "$log_file" 2>/dev/null || echo "0")
    if [ "$OVERFLOW" -gt 0 ]; then
        echo "  Heap-buffer-overflow: $OVERFLOW"
    fi

    echo ""
done

echo "========================================"
echo "SUMMARY"
echo "========================================"
echo "Total memory leaks: $TOTAL_LEAKS"
echo "Total ASan errors: $TOTAL_ERRORS"
echo ""

if [ "$TOTAL_LEAKS" -gt 0 ] || [ "$TOTAL_ERRORS" -gt 0 ]; then
    echo "RESULT: FAILED - Memory issues detected"
    echo ""
    echo "Full logs available in:"
    for log_file in $ASAN_LOGS; do
        echo "  - $log_file"
    done
    exit 1
else
    echo "RESULT: PASSED - No memory issues detected"
    exit 0
fi
