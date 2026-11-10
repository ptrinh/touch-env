#!/bin/sh
# Tests the parts of touchenv.swift that need no Keychain, Touch ID or window: SSH key parsing and signing, the agent
# protocol (against OpenSSH's own ssh-add, ssh-keygen and, with --sshd, a throwaway sshd), ssh-agent loading, grant
# matching, and the steps printed after touchenv ssh add.
#   tests/run.sh [--sshd]
# Everything happens in a temp folder: no key, agent, config or known_hosts of yours is read or touched (ssh runs
# with -F /dev/null and explicit files). touchenv.swift is compiled with -D TOUCHENV_TESTS, which leaves out its
# command dispatch, together with tests/ssh-tests.swift.
set -e
cd "$(dirname "$0")/.."
work=$(mktemp -d "${TMPDIR:-/tmp}/touchenv-tests.XXXXXX")
trap 'rm -rf "$work"' EXIT
cat touchenv.swift tests/ssh-tests.swift > "$work/main.swift"
swiftc -O -D TOUCHENV_TESTS "$work/main.swift" -o "$work/ssh-tests"
TOUCHENV_TEST_DIR="$work" "$work/ssh-tests" "$@"
