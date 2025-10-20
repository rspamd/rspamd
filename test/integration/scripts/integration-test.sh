#!/bin/bash
# Rspamd Integration Test using rspamc
# This script tests fuzzy storage, Bayes learning, and scanning via rspamc

set -e

# Disable leak detection for rspamc utility to avoid false positives
export ASAN_OPTIONS=detect_leaks=0

# Configuration
RSPAMD_HOST=${RSPAMD_HOST:-localhost}
CONTROLLER_PORT=${CONTROLLER_PORT:-50002}
PROXY_PORT=${PROXY_PORT:-50004}
PASSWORD=${PASSWORD:-q1}
PARALLEL=${PARALLEL:-10}
TRAIN_RATIO=${TRAIN_RATIO:-0.1}
TEST_PROXY=${TEST_PROXY:-false}

# Directories
# When running inside container via stdin, BASH_SOURCE won't work properly
if [ -d "/corpus" ]; then
    # Running inside container
    CORPUS_DIR="${CORPUS_DIR:-/corpus}"
    DATA_DIR="${DATA_DIR:-/data}"
else
    # Running on host
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    DATA_DIR="$SCRIPT_DIR/../data"
    CORPUS_DIR="${CORPUS_DIR:-$SCRIPT_DIR/../../functional/messages}"
fi

# Create working directory
mkdir -p "$DATA_DIR"

echo "=== Rspamd Integration Test ==="
echo ""
echo "Configuration:"
echo "  Host: $RSPAMD_HOST"
echo "  Controller port: $CONTROLLER_PORT"
echo "  Proxy port: $PROXY_PORT"
echo "  Parallelism: $PARALLEL"
echo "  Corpus: $CORPUS_DIR"
echo ""

# Check if rspamc is available
if ! command -v rspamc &> /dev/null; then
    echo "ERROR: rspamc not found. Running inside docker container..."
    exec docker compose exec -T \
        -e RSPAMD_HOST="$RSPAMD_HOST" \
        -e CONTROLLER_PORT="$CONTROLLER_PORT" \
        -e PROXY_PORT="$PROXY_PORT" \
        -e PASSWORD="$PASSWORD" \
        -e PARALLEL="$PARALLEL" \
        -e TRAIN_RATIO="$TRAIN_RATIO" \
        -e TEST_PROXY="$TEST_PROXY" \
        -e ASAN_OPTIONS="detect_leaks=0" \
        rspamd bash -s < "$0"
fi

# Check if Rspamd is running
echo "Checking Rspamd status..."
if ! rspamc -h "$RSPAMD_HOST:$CONTROLLER_PORT" -P "$PASSWORD" stat &> /dev/null; then
    echo "ERROR: Cannot connect to Rspamd at $RSPAMD_HOST:$CONTROLLER_PORT"
    exit 1
fi
echo "✓ Rspamd is running"
echo ""

# Find all email files, filtering by size (min 200 bytes to have enough tokens)
echo "Finding email files in $CORPUS_DIR..."
MIN_SIZE=200  # bytes, roughly 11+ tokens for Bayes

# Find files with minimum size and verify they're readable
mapfile -t EMAIL_FILES < <(find "$CORPUS_DIR" -type f -readable -size +${MIN_SIZE}c \( -name "*.eml" -o -name "*.msg" -o -name "*.txt" \))
TOTAL_EMAILS=${#EMAIL_FILES[@]}

if [ $TOTAL_EMAILS -eq 0 ]; then
    echo "ERROR: No email files found in $CORPUS_DIR (min size: $MIN_SIZE bytes)"
    exit 1
fi

echo "Found $TOTAL_EMAILS email files (filtered by min size: $MIN_SIZE bytes)"
echo ""

# Calculate split sizes (using bash arithmetic)
FUZZY_SIZE=$(awk "BEGIN {printf \"%.0f\", $TOTAL_EMAILS * $TRAIN_RATIO}")
BAYES_SIZE=$(awk "BEGIN {printf \"%.0f\", $TOTAL_EMAILS * $TRAIN_RATIO}")

# Split corpus into lists (no copying needed)
echo "Splitting corpus into training sets..."
shuf -e "${EMAIL_FILES[@]}" > "$DATA_DIR/shuffled_files.txt"

# Fuzzy training set
head -n "$FUZZY_SIZE" "$DATA_DIR/shuffled_files.txt" > "$DATA_DIR/fuzzy_train_list.txt"
FUZZY_COUNT=$(wc -l < "$DATA_DIR/fuzzy_train_list.txt")

# Bayes training set (spam)
tail -n +$((FUZZY_SIZE + 1)) "$DATA_DIR/shuffled_files.txt" | head -n "$BAYES_SIZE" > "$DATA_DIR/bayes_spam_list.txt"
SPAM_COUNT=$(wc -l < "$DATA_DIR/bayes_spam_list.txt")

# Bayes training set (ham)
tail -n +$((FUZZY_SIZE + BAYES_SIZE + 1)) "$DATA_DIR/shuffled_files.txt" | head -n "$BAYES_SIZE" > "$DATA_DIR/bayes_ham_list.txt"
HAM_COUNT=$(wc -l < "$DATA_DIR/bayes_ham_list.txt")

echo "Corpus split:"
echo "  Fuzzy training: $FUZZY_COUNT emails"
echo "  Bayes SPAM training: $SPAM_COUNT emails"
echo "  Bayes HAM training: $HAM_COUNT emails"
echo "  Test set: $TOTAL_EMAILS emails"
echo ""

# Training phase
echo "============================================================"
echo "TRAINING PHASE"
echo "============================================================"
echo ""

# Train fuzzy storage
echo "Training Fuzzy storage ($FUZZY_COUNT emails, flag=1)..."
if [ $FUZZY_COUNT -gt 0 ]; then
    while IFS= read -r file; do
        rspamc -h "$RSPAMD_HOST:$CONTROLLER_PORT" -P "$PASSWORD" \
            fuzzy_add "$file" -f 1 -w 10
    done < "$DATA_DIR/fuzzy_train_list.txt" 2>&1 | tee "$DATA_DIR/fuzzy_train.log"
    echo "✓ Fuzzy training complete"
else
    echo "⚠ No files to train"
fi
echo ""

# Train Bayes spam
echo "Training Bayes SPAM ($SPAM_COUNT emails)..."
if [ $SPAM_COUNT -gt 0 ]; then
    while IFS= read -r file; do
        rspamc -h "$RSPAMD_HOST:$CONTROLLER_PORT" -P "$PASSWORD" \
            learn_spam "$file"
    done < "$DATA_DIR/bayes_spam_list.txt" 2>&1 | tee "$DATA_DIR/bayes_spam.log"
    echo "✓ Bayes SPAM training complete"
else
    echo "⚠ No files to train"
fi
echo ""

# Train Bayes ham
echo "Training Bayes HAM ($HAM_COUNT emails)..."
if [ $HAM_COUNT -gt 0 ]; then
    while IFS= read -r file; do
        rspamc -h "$RSPAMD_HOST:$CONTROLLER_PORT" -P "$PASSWORD" \
            learn_ham "$file"
    done < "$DATA_DIR/bayes_ham_list.txt" 2>&1 | tee "$DATA_DIR/bayes_ham.log"
    echo "✓ Bayes HAM training complete"
else
    echo "⚠ No files to train"
fi
echo ""

# Wait for training to settle
echo "Waiting for training to settle..."
sleep 5
echo ""

# Scanning phase
echo "============================================================"
echo "SCANNING PHASE (via controller)"
echo "============================================================"
echo ""

echo "Scanning $TOTAL_EMAILS emails (parallelism: $PARALLEL)..."
# Scan the same files we used for training (from shuffled list)
# Use xargs with -a to read from file and avoid argument list too long
xargs -a "$DATA_DIR/shuffled_files.txt" rspamc -h "$RSPAMD_HOST:$CONTROLLER_PORT" \
    -P "$PASSWORD" -n "$PARALLEL" -j > "$DATA_DIR/results.json" 2>&1

echo "✓ Scanning complete"
echo ""

# Analyze results
echo "============================================================"
echo "ANALYSIS"
echo "============================================================"
echo ""

# Count detections using grep and jq (or grep if jq not available)
if command -v jq &> /dev/null; then
    # Use jq for JSON parsing
    TOTAL=$(jq 'length' "$DATA_DIR/results.json")
    FUZZY_COUNT=$(jq '[.[] | select(.symbols | keys[] | startswith("FUZZY_"))] | length' "$DATA_DIR/results.json")
    BAYES_SPAM_COUNT=$(jq '[.[] | select(.symbols.BAYES_SPAM)] | length' "$DATA_DIR/results.json")
    BAYES_HAM_COUNT=$(jq '[.[] | select(.symbols.BAYES_HAM)] | length' "$DATA_DIR/results.json")
else
    # Fallback to grep
    TOTAL=$(grep -c '"symbols"' "$DATA_DIR/results.json" || echo 0)
    FUZZY_COUNT=$(grep -c '"FUZZY_' "$DATA_DIR/results.json" || echo 0)
    BAYES_SPAM_COUNT=$(grep -c '"BAYES_SPAM"' "$DATA_DIR/results.json" || echo 0)
    BAYES_HAM_COUNT=$(grep -c '"BAYES_HAM"' "$DATA_DIR/results.json" || echo 0)
fi

if [ "$TOTAL" -eq 0 ]; then
    echo "ERROR: No valid results"
    exit 1
fi

# Ensure counts are numeric (default to 0 if empty or non-numeric)
FUZZY_COUNT=$(echo "$FUZZY_COUNT" | grep -E '^[0-9]+$' || echo 0)
BAYES_SPAM_COUNT=$(echo "$BAYES_SPAM_COUNT" | grep -E '^[0-9]+$' || echo 0)
BAYES_HAM_COUNT=$(echo "$BAYES_HAM_COUNT" | grep -E '^[0-9]+$' || echo 0)
TOTAL=$(echo "$TOTAL" | grep -E '^[0-9]+$' || echo 0)

# Calculate percentages using awk (pass variables safely)
FUZZY_RATE=$(awk -v count="$FUZZY_COUNT" -v total="$TOTAL" 'BEGIN {printf "%.1f", (count / total) * 100}')
BAYES_SPAM_RATE=$(awk -v count="$BAYES_SPAM_COUNT" -v total="$TOTAL" 'BEGIN {printf "%.1f", (count / total) * 100}')
BAYES_HAM_RATE=$(awk -v count="$BAYES_HAM_COUNT" -v total="$TOTAL" 'BEGIN {printf "%.1f", (count / total) * 100}')

echo "Total scanned: $TOTAL"
echo "Fuzzy detections: $FUZZY_COUNT ($FUZZY_RATE%)"
echo "Bayes SPAM: $BAYES_SPAM_COUNT ($BAYES_SPAM_RATE%)"
echo "Bayes HAM: $BAYES_HAM_COUNT ($BAYES_HAM_RATE%)"
echo ""

# Validation (fuzzy should detect ~10% since we trained on 10%)
echo "Validation:"
FUZZY_RATE_INT=$(echo "$FUZZY_RATE" | cut -d. -f1)
BAYES_SPAM_RATE_INT=$(echo "$BAYES_SPAM_RATE" | cut -d. -f1)

if [ "$FUZZY_RATE_INT" -ge 5 ] && [ "$FUZZY_RATE_INT" -le 15 ]; then
    echo "  ✓ Fuzzy detection rate: PASS"
else
    echo "  ✗ Fuzzy detection rate: FAIL (expected ~10%, got $FUZZY_RATE%)"
fi

if [ "$BAYES_SPAM_RATE_INT" -ge 5 ]; then
    echo "  ✓ Bayes detection: PASS"
else
    echo "  ✗ Bayes detection: FAIL (got $BAYES_SPAM_RATE%)"
fi

# Test via proxy if requested
if [ "$TEST_PROXY" = "true" ]; then
    echo ""
    echo "============================================================"
    echo "PROXY TEST"
    echo "============================================================"
    echo ""

    echo "Testing via proxy worker ($PROXY_PORT)..."
    # Use corpus directory for proxy test too
    rspamc -h "$RSPAMD_HOST:$PROXY_PORT" -n "$PARALLEL" -j \
        "$CORPUS_DIR" > "$DATA_DIR/proxy_results.json" 2>&1
    echo "✓ Proxy test complete"
    echo "Results saved to $DATA_DIR/proxy_results.json"
fi

echo ""
echo "============================================================"
echo "TEST COMPLETE"
echo "============================================================"
echo ""
echo "Results saved to:"
echo "  - $DATA_DIR/results.json"
echo "  - $DATA_DIR/fuzzy_train.log"
echo "  - $DATA_DIR/bayes_spam.log"
echo "  - $DATA_DIR/bayes_ham.log"
