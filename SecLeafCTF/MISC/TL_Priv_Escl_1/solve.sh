#!/usr/bin/env bash
# Base64 string recovered from /root/root/.../flag.txt
B64="bG9jYWxfZXNjbDR0M19yMDB0"

DECODED=$(echo -n "$B64" | base64 -d)
echo "Decoded payload: $DECODED"
echo "Flag: SecLeaf{$DECODED}"
