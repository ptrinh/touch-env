#!/bin/sh
# Checks a touchenv binary against conformance/cases.txt:  conformance/run.sh path/to/touchenv
# Every case ends before touchenv reads a secret or asks for Touch ID / Windows Hello, so it is safe to run against
# a real install. On Windows, run it from Git Bash with the path to touchenv.exe.
set -u
bin=${1:?usage: conformance/run.sh path/to/touchenv}
cases="$(dirname "$0")/cases.txt"
pass=0 failed=0
out=$(mktemp) err=$(mktemp)
trap 'rm -f "$out" "$err"' EXIT
platform=macos
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) platform=windows ;; esac
case "$bin" in *.exe) platform=windows ;; esac
while IFS='|' read -r want check args; do
  case "$want" in ''|\#*) continue ;; esac
  case "$want" in
    windows:*|macos:*) [ "${want%%:*}" = "$platform" ] || continue; want=${want#*:} ;;
  esac
  want=$(echo "$want" | tr -d ' ')
  check=$(echo "$check" | sed 's/^ *//; s/ *$//')
  # shellcheck disable=SC2086  # the arguments are space separated on purpose
  "$bin" $args </dev/null >"$out" 2>"$err"
  got=$?
  stream=${check%%:*} text=${check#*:}
  file=$err; [ "$stream" = out ] && file=$out
  if [ "$got" = "$want" ] && { [ "$check" = - ] || grep -qF -- "$text" "$file"; }; then
    pass=$((pass + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: touchenv$args: exit $got (want $want), want $stream to contain: $text"
    sed 's/^/  | /' "$err" | head -3
  fi
done <"$cases"
echo "$pass passed, $failed failed"
[ "$failed" = 0 ]
