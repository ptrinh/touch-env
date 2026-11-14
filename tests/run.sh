#!/bin/sh
# Tests the parts of touchenv.swift that need no Keychain, Touch ID or window: SSH key parsing and signing, the agent
# protocol (against OpenSSH's own ssh-add, ssh-keygen and, with --sshd, a throwaway sshd), ssh-agent loading, grant
# matching, and the steps printed after touchenv ssh add (tests/ssh-tests.swift); standing grants, with real shells
# and signature checks but grants kept in memory, and the access log (tests/standing-tests.swift); --password on a
# pseudo-terminal with a fake password check (tests/password-tests.swift); masking secrets in a command's output
# (tests/mask-tests.swift).
#   tests/run.sh [--sshd]
# Everything happens in a temp folder: no key, agent, config or known_hosts of yours is read or touched (ssh runs
# with -F /dev/null and explicit files). touchenv.swift is compiled with -D TOUCHENV_TESTS, which leaves out its
# command dispatch, together with tests/ssh-tests.swift.
set -e
cd "$(dirname "$0")/.."
work=$(mktemp -d "${TMPDIR:-/tmp}/touchenv-tests.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir "$work/ssh" "$work/standing" "$work/password" "$work/mask"
cat touchenv.swift tests/ssh-tests.swift > "$work/ssh/main.swift"
swiftc -O -D TOUCHENV_TESTS "$work/ssh/main.swift" -o "$work/ssh/ssh-tests"
cat touchenv.swift tests/standing-tests.swift > "$work/standing/main.swift"
swiftc -O -D TOUCHENV_TESTS "$work/standing/main.swift" -o "$work/standing/standing-tests"
cat touchenv.swift tests/password-tests.swift > "$work/password/main.swift"
swiftc -O -D TOUCHENV_TESTS "$work/password/main.swift" -o "$work/password/password-tests"
cat touchenv.swift tests/mask-tests.swift > "$work/mask/main.swift"
swiftc -O -D TOUCHENV_TESTS "$work/mask/main.swift" -o "$work/mask/mask-tests"
echo "masking tests:"
"$work/mask/mask-tests"
echo "ssh tests:"
TOUCHENV_TEST_DIR="$work/ssh" "$work/ssh/ssh-tests" "$@"
echo "standing grant and access log tests:"
TOUCHENV_TEST_DIR="$work/standing" "$work/standing/standing-tests"
echo "--password tests:"
TOUCHENV_TEST_DIR="$work/password" "$work/password/password-tests"
