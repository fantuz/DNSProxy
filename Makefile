include modern.mk

# Report retirement even when an old dnsp executable exists in the checkout.
.PHONY: dnsp
dnsp:
	@printf '%s\n' "$@ is retired. Run make to build dnsp-modern." >&2
	@exit 1
