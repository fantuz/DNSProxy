CC ?= cc
CFLAGS ?= -O2 -g
PKG_CONFIG ?= pkg-config
CURL_FLAGS := $(shell $(PKG_CONFIG) --cflags --libs libcurl)

.PHONY: all modern-check clean
all: dnsp-modern

dnsp-modern: dnsp-modern.c modern.mk
	$(CC) $(CPPFLAGS) -std=c11 $(CFLAGS) -Wall -Wextra -Wpedantic $(LDFLAGS) -o $@ $< $(CURL_FLAGS) $(LDLIBS)

modern-check: dnsp-modern
	@set -e; probe=$$(mktemp); trap 'rm -f "$$probe"' 0; \
	$(CC) $(CPPFLAGS) -std=c11 $(CFLAGS) -Wall -Wextra -Wpedantic $(LDFLAGS) -o "$$probe" tests/test_curl_callbacks.c $(CURL_FLAGS) $(LDLIBS); \
	"$$probe"
	python3 tests/test_modern.py

clean:
	rm -f dnsp-modern

# Optional TLS/HTTP2 benchmarking deps: python3, hypercorn, h2, openssl.
.PHONY: benchmark-smoke
benchmark-smoke: dnsp-modern
	python3 -m unittest discover -s tests -p 'test_benchmark.py' -v
