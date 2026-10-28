#!/bin/sh
# Syntax-check every module as an ES module, the way Workers loads them.
set -e
fail=0
for f in *.js; do
  out=$(node --input-type=module --check < "$f" 2>&1) || true
  if [ -n "$out" ]; then
    echo "=== $f ==="
    echo "$out" | head -8
    fail=1
  fi
done
[ "$fail" -eq 0 ] && echo "syntax: all modules OK"
exit "$fail"
