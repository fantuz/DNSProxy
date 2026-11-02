CC ?= cc
CFLAGS ?= -O2 -g
CURL_FLAGS := $(shell pkg-config --cflags --libs libcurl)

.PHONY: all modern-check clean
all: dnsp-modern

dnsp-modern: dnsp-modern.c
	$(CC) -std=c11 $(CFLAGS) -Wall -Wextra -Wpedantic -o $@ $< $(CURL_FLAGS)

modern-check: dnsp-modern
	python3 tests/test_modern.py

clean:
	rm -f dnsp-modern
