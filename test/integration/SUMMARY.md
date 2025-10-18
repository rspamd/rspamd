# Rspamd Integration Test - Summary

## Overview

Complete integration and load testing infrastructure for Rspamd with Docker Compose.

## Features

### 1. Complete Rspamd Environment
- **Scanner workers** (2x) with encryption
- **Controller worker** for API access
- **Proxy worker** for request proxying with encryption
- **Fuzzy storage** with encrypted connections
- **Redis** backend for data storage
- **Bayes classifier** for spam detection

### 2. AddressSanitizer Integration
- **Image**: `rspamd/rspamd:asan-latest`
- Detects memory leaks, buffer overflows, use-after-free
- Automatic log analysis with `check-asan-logs.sh`
- Configurable suppressions via `lsan.supp`

### 3. Comprehensive Testing
- Downloads email corpus from URL or uses local files
- Trains Fuzzy storage (10% of corpus)
- Trains Bayes classifier (10% spam + 10% ham)
- Scans entire corpus
- Validates detection rates (~10% expected)
- Tests both controller and proxy workers

### 4. High Ports Configuration
All services use ports 50000+ to avoid conflicts:
- 50001: Scanner workers
- 50002: Controller API
- 50003: Fuzzy storage
- 50004: Proxy worker

### 5. Full Encryption
- Fuzzy storage: encrypted-only mode
- Scanner workers: keypair encryption
- Proxy worker: keypair encryption
- All keys auto-generated via `generate-keys.sh`

## Quick Start

```bash
cd test/integration
make keys        # Generate encryption keys
make up          # Start Docker environment
make test        # Run integration test
make check-asan  # Check for memory issues
make down        # Stop environment
```

## Files Created

### Configuration
- `configs/rspamd.conf` - Main Rspamd configuration
- `configs/worker-*.inc` - Worker configurations
- `configs/fuzzy_check.conf` - Fuzzy module settings
- `configs/redis.conf` - Redis backend
- `configs/statistic.conf` - Bayes classifier
- `configs/lsan.supp` - LeakSanitizer suppressions
- `configs/fuzzy-keys.conf` - Generated encryption keys

### Scripts
- `scripts/generate-keys.sh` - Generate encryption keys for all workers
- `scripts/integration-test.py` - Main test script with training and validation
- `scripts/check-asan-logs.sh` - Analyze AddressSanitizer logs

### Infrastructure
- `docker-compose.yml` - Docker Compose setup with ASan
- `Makefile` - Convenient commands
- `README.md` - Complete documentation
- `.gitignore` - Ignore temporary files

## GitHub Actions Workflow

`.github/workflows/integration-test.yml` provides:
- Automated testing on push/PR
- Daily scheduled runs
- Manual runs with custom corpus URL
- ASan log analysis
- Artifact uploads (results, logs)

## Test Parameters

```bash
./scripts/integration-test.py \
  --corpus-url https://example.com/emails.zip \
  --rspamd-host localhost \
  --rspamd-port 50002 \
  --proxy-port 50004 \
  --train-ratio 0.1 \
  --test-proxy \
  --output results.json
```

## Results

Test outputs:
- `data/results.json` - Controller scan results
- `data/proxy_results.json` - Proxy scan results (if --test-proxy)
- `data/asan.log*` - AddressSanitizer logs

## Validation

The test validates:
- Fuzzy detection rate ~10% (±5% tolerance)
- Bayes detection rate ~10% (±5% tolerance)
- No critical memory issues (via ASan)
- Proxy worker functionality

## Performance Testing

To increase load:
1. Increase worker count in `configs/worker-normal.inc`
2. Use larger email corpus
3. Run multiple test instances in parallel
4. Adjust timeout and task limits

## Memory Safety

ASan configuration:
```
ASAN_OPTIONS=detect_leaks=1:halt_on_error=0:abort_on_error=0:print_stats=1:log_path=/data/asan.log
LSAN_OPTIONS=suppressions=/etc/rspamd/lsan.supp:print_suppressions=0
```

Use `make check-asan` to analyze logs and detect:
- Memory leaks
- Heap-use-after-free
- Heap-buffer-overflow
- Double-free
- Use-after-return

## Next Steps

1. **Local Testing**: Run `make all` to test locally
2. **Custom Corpus**: Provide your own email corpus via `--corpus-url`
3. **CI/CD Integration**: Push to trigger GitHub Actions workflow
4. **Tune Parameters**: Adjust training ratios, worker counts, timeouts
5. **Monitor ASan**: Check logs regularly for memory issues
