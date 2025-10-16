# Rspamd Integration and Load Testing

Comprehensive integration and load testing for Rspamd using Docker Compose.

## Description

This test creates a complete Rspamd environment with:

- Scanner workers for processing emails (with encryption)
- Controller worker for management
- Proxy worker for proxying requests (with encryption)
- Fuzzy storage with encryption
- Redis for data storage
- Bayes classifier

The test performs the following steps:

1. Downloads email corpus from a given URL (or uses local test emails)
2. Trains Fuzzy storage on 10% of emails
3. Trains Bayes classifier on 10% of emails (spam and ham)
4. Scans the entire corpus
5. Validates that detection works correctly (~10% detection rate)

## Requirements

- Docker and Docker Compose
- Python 3.8+
- rspamadm (for key generation)

## Features

This test uses **AddressSanitizer (ASan)** to detect:

- Memory leaks
- Buffer overflows
- Use-after-free errors
- Other memory issues

Docker image: `rspamd/rspamd:asan-latest`

## Quick Start

### 1. Generate encryption keys

```bash
cd test/integration
./scripts/generate-keys.sh
```

### 2. Start environment

```bash
docker compose up -d
```

### 3. Check readiness

```bash
docker compose ps
docker compose logs rspamd
```

### 4. Run test

```bash
# With local corpus (uses test/functional/messages)
./scripts/integration-test.py

# With remote corpus
./scripts/integration-test.py --corpus-url https://example.com/emails.zip

# With local directory
./scripts/integration-test.py --corpus-dir /path/to/emails
```

### 5. Check for memory leaks

```bash
make check-asan
```

This script analyzes AddressSanitizer logs and reports any detected memory leaks.

### 6. Stop

```bash
docker compose down
```

## Test Parameters

```bash
./scripts/integration-test.py --help

Options:
  --corpus-url URL          URL to download email corpus from
  --corpus-dir DIR          Directory containing email corpus
  --rspamd-host HOST        Rspamd host (default: localhost)
  --rspamd-port PORT        Controller port (default: 50002)
  --proxy-port PORT         Proxy port (default: 50004)
  --password PASS           Password (default: q1)
  --train-ratio RATIO       Training ratio (default: 0.1 = 10%)
  --output FILE             Output file for results (default: results.json)
  --test-proxy              Also test via proxy worker
```

## Project Structure

```
test/integration/
├── docker-compose.yml          # Docker Compose configuration
├── configs/                    # Rspamd configurations
│   ├── worker-normal.inc      # Scanner worker
│   ├── worker-controller.inc  # Controller worker
│   ├── worker-proxy.inc       # Proxy worker
│   ├── worker-fuzzy.inc       # Fuzzy storage worker
│   ├── fuzzy_check.conf       # fuzzy_check module
│   ├── redis.conf             # Redis settings
│   ├── statistic.conf         # Bayes classifier
│   ├── lsan.supp              # LeakSanitizer suppressions
│   └── fuzzy-keys.conf        # Encryption keys (generated)
├── scripts/
│   ├── generate-keys.sh       # Key generation
│   ├── integration-test.py    # Test script
│   └── check-asan-logs.sh     # ASan log checker
├── data/                       # Data (corpus, results)
└── README.md
```

## Configuration

### Ports

- `50001` - Normal worker (scanning)
- `50002` - Controller (API)
- `50003` - Fuzzy storage
- `50004` - Proxy worker

### Environment Variables

In `docker-compose.yml` you can configure:

- `REDIS_ADDR` - Redis address
- `REDIS_PORT` - Redis port
- `ASAN_OPTIONS` - AddressSanitizer options
- `LSAN_OPTIONS` - LeakSanitizer options

### Encryption

Fuzzy storage uses encryption. Keys are generated automatically when running `generate-keys.sh`.

## Results

Results are saved in `data/results.json` in the following format:

```json
[
  {
    "file": "message1.eml",
    "score": 5.2,
    "symbols": {
      "FUZZY_SPAM": 2.5,
      "BAYES_SPAM": 3.0
    }
  },
  ...
]
```

## Debugging

### Check logs

```bash
# All logs
docker compose logs

# Only Rspamd
docker compose logs rspamd

# Follow logs
docker compose logs -f rspamd
```

### Connect to container

```bash
docker compose exec rspamd /bin/sh
```

### Check Rspamd operation

```bash
# Ping (Controller)
curl http://localhost:50002/ping

# Ping (Proxy)
curl http://localhost:50004/ping

# Statistics
curl -H "Password: q1" http://localhost:50002/stat

# Scan test email (via Controller)
curl -H "Password: q1" --data-binary @test.eml http://localhost:50002/checkv2

# Scan via Proxy
curl -H "Password: q1" --data-binary @test.eml http://localhost:50004/checkv2
```

### Check Fuzzy storage

```bash
# Fuzzy statistics
curl -H "Password: q1" http://localhost:50002/fuzzystats
```

### Test via Proxy

```bash
# Run test with proxy check
./scripts/integration-test.py --test-proxy

# Results will be saved in:
# - data/results.json (via controller)
# - data/proxy_results.json (via proxy)
```

## CI/CD

See `.github/workflows/integration-test.yml` for automated runs in GitHub Actions.

## AddressSanitizer

### View ASan logs

```bash
# Logs are saved in data/asan.log*
cat data/asan.log*

# Automatic check
make check-asan
```

### ASan Configuration

In `docker-compose.yml` the following options are configured:

```
ASAN_OPTIONS=detect_leaks=1:halt_on_error=0:abort_on_error=0:print_stats=1:log_path=/data/asan.log
```

- `detect_leaks=1` - detect memory leaks
- `halt_on_error=0` - don't stop on first error
- `abort_on_error=0` - don't call abort()
- `print_stats=1` - print statistics
- `log_path=/data/asan.log` - log file path

### Suppress False Positives

Edit `configs/lsan.supp`:

```
leak:function_name_to_suppress
```

## Troubleshooting

### Rspamd doesn't start

1. Check that keys are generated: `ls configs/fuzzy-keys.conf`
2. Check logs: `docker compose logs rspamd`
3. Check ASan logs: `cat data/asan.log*`

### Redis unavailable

```bash
docker compose exec redis redis-cli ping
```

### Low detection rate

- Increase corpus size
- Verify training completed successfully
- Check Rspamd logs

## Performance

For load testing you can:

- Increase number of scanner workers in `configs/worker-normal.inc`
- Increase corpus size
- Run multiple parallel test instances
