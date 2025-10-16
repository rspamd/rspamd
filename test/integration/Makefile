# Rspamd Integration Test Makefile

.PHONY: help keys build up down test test-proxy test-parallel clean logs check-asan

help:
	@echo "Rspamd Integration Test"
	@echo ""
	@echo "Available targets:"
	@echo "  keys         - Generate fuzzy encryption keys"
	@echo "  build        - Build Docker containers"
	@echo "  up           - Start Docker Compose services"
	@echo "  down         - Stop Docker Compose services"
	@echo "  test         - Run integration test"
	@echo "  test-proxy   - Run integration test including proxy"
	@echo "  test-parallel - Run integration test with custom parallelism (PARALLEL=N)"
	@echo "  check-asan   - Check AddressSanitizer logs for memory issues"
	@echo "  clean        - Clean up data and logs"
	@echo "  logs         - Show Docker logs"
	@echo ""
	@echo "Quick start:"
	@echo "  make keys build up test"

keys:
	@echo "Generating fuzzy encryption keys..."
	@./scripts/generate-keys.sh

build:
	@echo "Building Docker containers..."
	@docker compose build

up:
	@echo "Cleaning previous data..."
	@rm -rf data/fuzzy_train data/bayes_spam data/bayes_ham data/test_corpus
	@rm -rf data/*.json data/*.log data/*.txt
	@mkdir -p data
	@echo "Starting Docker Compose services..."
	@docker compose up -d --force-recreate
	@echo "Waiting for services to be ready..."
	@sleep 10
	@docker compose ps

down:
	@echo "Stopping Docker Compose services..."
	@docker compose down

test:
	@echo "Running integration test..."
	@docker compose exec -T rspamd /bin/bash < ./scripts/integration-test.sh

test-proxy:
	@echo "Running integration test (including proxy)..."
	@TEST_PROXY=true docker compose exec -T rspamd /bin/bash < ./scripts/integration-test.sh

test-parallel:
	@echo "Running integration test (parallel=$(PARALLEL))..."
	@PARALLEL=$(PARALLEL) docker compose exec -T rspamd /bin/bash < ./scripts/integration-test.sh

clean:
	@echo "Cleaning up..."
	@rm -rf data/fuzzy_train data/bayes_spam data/bayes_ham data/test_corpus
	@rm -rf data/*.json data/*.log data/*.txt
	@docker compose down -v

logs:
	@docker compose logs -f

check-asan:
	@echo "Checking AddressSanitizer logs..."
	@./scripts/check-asan-logs.sh

restart: down up

all: keys build up test check-asan
