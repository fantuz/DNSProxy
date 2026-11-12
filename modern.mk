CC ?= cc
CFLAGS ?= -O2 -g
PKG_CONFIG ?= pkg-config
CURL_FLAGS := $(shell $(PKG_CONFIG) --cflags --libs libcurl)
DNSP_BUILD_VERSION := $(shell sed -nE '/^[0-9]+\.[0-9]+\.[0-9]+$$/p' VERSION)

.PHONY: all modern-check clean
all: dnsp-modern

dnsp-modern: dnsp-modern.c dnsp-platform.h modern.mk VERSION
	$(CC) $(CPPFLAGS) -DDNSP_VERSION='"$(DNSP_BUILD_VERSION)"' -std=c11 $(CFLAGS) -Wall -Wextra -Wpedantic $(LDFLAGS) -o $@ $< $(CURL_FLAGS) $(LDLIBS)

modern-check: dnsp-modern
	@set -e; probe=$$(mktemp); trap 'rm -f "$$probe"' 0; \
	$(CC) $(CPPFLAGS) -std=c11 $(CFLAGS) -Wall -Wextra -Wpedantic $(LDFLAGS) -o "$$probe" tests/test_curl_callbacks.c $(CURL_FLAGS) $(LDLIBS); \
	"$$probe"; \
	$(CC) $(CPPFLAGS) -std=c11 $(CFLAGS) -Wall -Wextra -Wpedantic $(LDFLAGS) -o "$$probe" tests/test_platform.c $(CURL_FLAGS) $(LDLIBS); \
	"$$probe"
	python3 tests/test_modern.py

clean:
	rm -f dnsp-modern

# Optional TLS/HTTP2 benchmarking deps: python3, hypercorn, h2, openssl.
.PHONY: benchmark-smoke
benchmark-smoke: dnsp-modern
	python3 -m unittest discover -s tests -p 'test_benchmark.py' -v

# Optional parser fuzzing with Clang and libFuzzer.
FUZZ_CC ?= clang
FUZZ_SECONDS ?= 30
.PHONY: modern-fuzz
modern-fuzz:
	@set -eu; run=$$(mktemp -d); trap 'rm -rf "$$run"' 0; \
	$(FUZZ_CC) $(CPPFLAGS) -std=c11 -O1 -g -Wall -Wextra -Wpedantic \
		-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
		$(LDFLAGS) -o "$$run/fuzz-dns" tests/fuzz_dns.c $(CURL_FLAGS) $(LDLIBS); \
	python3 tests/make_fuzz_corpus.py "$$run/corpus"; \
	"$$run/fuzz-dns" "$$run/corpus" -max_total_time=$(FUZZ_SECONDS) -max_len=65536 -timeout=5

# Prevent implicit builds of retired source files.
MAKEFLAGS += --no-builtin-rules
