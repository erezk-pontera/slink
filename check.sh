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
# Looking for a URL *anywhere* in a string is the shape code scanning calls
# incomplete URL substring sanitization: it can sit inside a longer one,
# with arbitrary hosts either side of it. It has been written here three
# times and caught three times, each costing a push and a review round, so
# it is caught here instead. Pull the host out and compare it, or assert on
# something that is not URL-shaped.
#
# startsWith and endsWith are left alone on purpose: anchored at one end
# against a whole origin, they are the shape that query recommends rather
# than the one it reports.
urls=$(grep -rnE "\.(includes|indexOf)\([\"']https?://" \
  --include='*.js' --include='*.mjs' . \
  | grep -v '/node_modules/' || true)
if [ -n "$urls" ]; then
  echo "=== a URL matched by substring ==="
  echo "$urls"
  echo "Compare an extracted host instead; see the note in check.sh."
  fail=1
fi

[ "$fail" -eq 0 ] && echo "syntax: all modules OK, no URL matched by substring"
exit "$fail"
