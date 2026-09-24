#!/bin/sh
#
# A log field must not carry key material — not whole, not a prefix.
#
# Until 2026-09-24 the X3DH and ratchet code logged the first bytes of the root key, of every
# DH output and of the *private* identity and signed prekeys, at `info`. Every one of those
# lines was written as a tracing field formatted straight from `hex::encode(...)`, so that is
# the shape this rejects. Log-safe forms live in `src/crypto/log_fingerprint.rs`:
# `secret_fingerprint(label, secret)` for "are these equal on both sides",
# `public_prefix(public)` for "which key was this".
#
# Run by CI (job `test`) and by .githooks/pre-push.

set -eu
cd "$(git rev-parse --show-toplevel)"

fail=0

# 1. A tracing field formatted directly from raw bytes: `name = %hex::encode(...)`.
if grep -rnE '[%?]hex::encode\(' src --include='*.rs'; then
    echo "::error::tracing field built from hex::encode — use log_fingerprint::{secret_fingerprint, public_prefix}"
    fail=1
fi

# 2. A tracing field whose very name says it is secret: `ik_priv_prefix = %...`, `secret = ?...`.
if grep -rnE '^\s*[a-z0-9_]*(priv|secret)[a-z0-9_]*\s*=\s*[%?]' src --include='*.rs'; then
    echo "::error::tracing field named as a private key / secret"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "secret-logging check: ok"
