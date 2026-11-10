include modern.mk

# Report retirement even when an old executable exists in the checkout.
.PHONY: dnsp dnsp-h2
dnsp dnsp-h2:
	@printf '%s\n' "$@ is retired. Run make to build dnsp-modern." >&2
	@exit 1
