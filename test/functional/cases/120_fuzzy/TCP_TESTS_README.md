# TCP Fuzzy Check Tests

This directory contains functional tests for TCP support in fuzzy_check plugin.

## Test Files

- **tcp.robot** - Basic TCP tests with auto-switch mode (tcp = "auto")
  - Tests TCP connection with rate-based switching
  - Threshold set to 5 requests/second

- **tcp-explicit.robot** - Explicit TCP mode tests (tcp = "yes")
  - Forces TCP usage for all fuzzy check operations

- **tcp-encrypted.robot** - Encrypted TCP tests
  - Tests TCP with encryption enabled on both client and server

## Running Tests

### Run all TCP tests:
```bash
cd /Users/vstakhov/rspamd
robot -v RSPAMD_INSTALLROOT:/path/to/install \
      -v RSPAMD_TESTDIR:/Users/vstakhov/rspamd/test/functional \
      test/functional/cases/120_fuzzy/tcp*.robot
```

### Run specific TCP test:
```bash
robot -v RSPAMD_INSTALLROOT:/path/to/install \
      -v RSPAMD_TESTDIR:/Users/vstakhov/rspamd/test/functional \
      test/functional/cases/120_fuzzy/tcp.robot
```

### Run with verbose output:
```bash
robot -v RSPAMD_INSTALLROOT:/path/to/install \
      -v RSPAMD_TESTDIR:/Users/vstakhov/rspamd/test/functional \
      -L DEBUG \
      test/functional/cases/120_fuzzy/tcp.robot
```

## Test Configuration

TCP tests use the following configuration:

### Auto mode (tcp.robot):
- `tcp = "auto"` - Enable automatic TCP switching
- `tcp_threshold = 5` - Switch to TCP after 5 requests/second

### Explicit mode (tcp-explicit.robot):
- `tcp = "yes"` - Always use TCP
- Server: `tcp = true` - Enable TCP on fuzzy worker

### Encrypted mode (tcp-encrypted.robot):
- `tcp = "auto"` with `tcp_threshold = 5`
- `encrypted_only = true` - Require encryption
- Shared keypair between client and server

## What is Tested

1. **Basic Operations**:
   - Add fuzzy hashes via TCP
   - Delete fuzzy hashes via TCP
   - Overwrite fuzzy hashes via TCP

2. **High Rate Scenario**:
   - Send multiple messages to exceed rate threshold
   - Verify automatic TCP switch
   - Verify fuzzy check continues to work

3. **Error Handling**:
   - Connection failures
   - Timeouts
   - Protocol errors

## Expected Results

All tests should pass, verifying:
- TCP connections are established correctly
- Fuzzy add/delete/overwrite operations work via TCP
- Auto-switch activates at rate threshold
- Encryption works with TCP
- UDP fallback works when TCP unavailable
