CC ?= cc
CFLAGS ?= -O2 -g
CURL_FLAGS := $(shell pkg-config --cflags --libs libcurl)

.PHONY: all modern-check clean
all: dnsp-modern

dnsp-modern: dnsp-modern.c
	$(CC) -std=c11 $(CFLAGS) -Wall -Wextra -Wpedantic -o $@ $< $(CURL_FLAGS)

modern-check: dnsp-modern
	@set -e; probe=$$(mktemp); trap 'rm -f "$$probe"' 0; \
	$(CC) -std=c11 $(CFLAGS) -Wall -Wextra -Wpedantic -o "$$probe" tests/test_curl_callbacks.c $(CURL_FLAGS); \
	"$$probe"
	python3 tests/test_modern.py

clean:
	rm -f dnsp-modern

# Optional TLS/HTTP2 benchmarking deps: python3, hypercorn, h2, openssl.
.PHONY: benchmark-smoke
benchmark-smoke: dnsp-modern
	python3 -m unittest discover -s tests -p 'test_benchmark.py' -v

# Prevent implicit builds of retired source files.
MAKEFLAGS += --no-builtin-rules
