#!/usr/bin/env bash
# Build, sign and zip touchenv for Windows, on a Mac (maintainer only). Run it after `gh release create v<version>`
# for the Mac app; it uploads nothing, and prints the `gh release upload` command to run.
#
#   windows/release.sh [--unsigned]
#
#  1. Cross-compiles touchenv.exe for x64 and arm64 with the same flags the CI uses (.github/workflows/windows.yml),
#     version from touchenv.swift's `let version`.
#  2. Signs both with jsign through Azure Trusted Signing (Authenticode, RFC 3161 timestamp from Microsoft's TSA).
#  3. Verifies each signature with osslsigncode against Microsoft's Identity Verification root (the PEM next to this
#     script), fails unless the signature and the timestamp check and the signer's CN is TOUCHENV_EXPECTED_PUBLISHER.
#  4. Zips each exe with LICENSE as dist/touchenv-<version>-windows-{x64,arm64}.zip, writes a .sha256 for each, and
#     checks the zip holds the very exe that was verified.
#
# Signing target: TOUCHENV_SIGN_ENDPOINT (e.g. https://weu.codesigning.azure.net), TOUCHENV_SIGN_ACCOUNT,
# TOUCHENV_SIGN_PROFILE and TOUCHENV_EXPECTED_PUBLISHER (the certificate's subject CN), from the environment or from
# the git-ignored windows/signing.local.env. Without them the script refuses, unless --unsigned (zips then named
# ...-UNSIGNED.zip, never to be attached to a release). Token: `az login` (the account needs the "Trusted Signing
# Certificate Profile Signer" role), or AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET. Nothing secret is
# written to disk or printed.
#
# Tools: go, jsign, osslsigncode, az (or the AZURE_* variables), zip, shasum.
#
# microsoft-identity-verification-root-2020.pem: Microsoft Identity Verification Root Certificate Authority 2020,
# the root Trusted Signing certificates chain to, from Microsoft's PKI repository
# (https://www.microsoft.com/pkiops/certs/Microsoft%20Identity%20Verification%20Root%20Certificate%20Authority%202020.crt,
# converted to PEM). Its SHA-256 fingerprint is checked below.
set -euo pipefail

WIN="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$WIN/.." && pwd)"
DIST="$ROOT/dist"
ROOTPEM="$WIN/microsoft-identity-verification-root-2020.pem"
ROOT_SHA256="53:67:F2:0C:7A:DE:0E:2B:CA:79:09:15:05:6D:08:6B:72:0C:33:C1:FA:2A:26:61:AC:F7:87:E3:29:2E:12:70"
MODULE="github.com/ptrinh/touch-env/windows"

UNSIGNED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --unsigned) UNSIGNED=1; shift ;;
    *) echo "usage: $0 [--unsigned]" >&2; exit 2 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 1; }; }
for t in go zip unzip shasum; do need "$t"; done

VERSION="$(sed -n 's/^let version = "\(.*\)"$/\1/p' "$ROOT/touchenv.swift")"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "can't read the version from touchenv.swift" >&2; exit 1; }
if [ -n "$(git -C "$ROOT" status --porcelain -- windows touchenv.swift LICENSE)" ]; then
  echo "warning: windows/, touchenv.swift or LICENSE has uncommitted changes; the build won't match the tag" >&2
fi

# ------------------------------------------------------------------ signing configuration
if [ "$UNSIGNED" = 0 ]; then
  for t in jsign osslsigncode openssl; do need "$t"; done
  if [ -f "$WIN/signing.local.env" ]; then
    # shellcheck disable=SC1091
    set -a; . "$WIN/signing.local.env"; set +a
  fi
  for v in TOUCHENV_SIGN_ENDPOINT TOUCHENV_SIGN_ACCOUNT TOUCHENV_SIGN_PROFILE TOUCHENV_EXPECTED_PUBLISHER; do
    [ -n "${!v:-}" ] || { echo "signing target not configured: $v (environment or windows/signing.local.env), or pass --unsigned" >&2; exit 1; }
  done
  got="$(openssl x509 -in "$ROOTPEM" -noout -fingerprint -sha256 | sed 's/^.*=//')"
  [ "$got" = "$ROOT_SHA256" ] || { echo "$ROOTPEM is not the Microsoft Identity Verification root (fingerprint $got)" >&2; exit 1; }
fi

signing_token() {
  if [ -n "${AZURE_TENANT_ID:-}" ] && [ -n "${AZURE_CLIENT_ID:-}" ] && [ -n "${AZURE_CLIENT_SECRET:-}" ]; then
    curl -fsS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
      -d "client_id=${AZURE_CLIENT_ID}" -d "client_secret=${AZURE_CLIENT_SECRET}" \
      -d "scope=https://codesigning.azure.net/.default" -d "grant_type=client_credentials" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
    return
  fi
  command -v az >/dev/null 2>&1 || return 1
  az account get-access-token --scope https://codesigning.azure.net/.default --query accessToken -o tsv 2>/dev/null
}

TOKEN=""
sign() {  # sign <file>
  if [ -z "$TOKEN" ]; then
    TOKEN="$(signing_token)" || TOKEN=""
    [ -n "$TOKEN" ] || { echo "no Azure signing token: run 'az login', or set AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET" >&2; exit 1; }
  fi
  jsign --storetype TRUSTEDSIGNING --keystore "$TOUCHENV_SIGN_ENDPOINT" --storepass "$TOKEN" \
    --alias "$TOUCHENV_SIGN_ACCOUNT/$TOUCHENV_SIGN_PROFILE" \
    --name "touchenv" --url https://github.com/ptrinh/touch-env \
    --tsaurl http://timestamp.acs.microsoft.com/ --tsmode RFC3161 "$1" >/dev/null \
    || { echo "signing failed: $1" >&2; exit 1; }
}

verify() {  # verify <file>: read the signature back off the bytes, against the Microsoft root; fail closed
  local f="$1" out
  out="$(osslsigncode verify -CAfile "$ROOTPEM" -TSA-CAfile "$ROOTPEM" "$f" 2>&1)" \
    || { echo "$out" >&2; echo "signature does not verify: $f" >&2; exit 1; }
  grep -qx "Signature verification: ok" <<<"$out" || { echo "$out" >&2; echo "signature does not verify: $f" >&2; exit 1; }
  grep -q "Timestamp Server Signature verification: ok" <<<"$out" \
    || { echo "$out" >&2; echo "no valid timestamp: $f" >&2; exit 1; }
  # The first "Subject:" is the signing certificate's ("Signer's certificate: Signer #0"); its CN must be exactly
  # the publisher (osslsigncode prints "CN=…,O=…" or "/CN=…/O=…" depending on its OpenSSL).
  grep -m1 "Subject:" <<<"$out" | sed 's/^[[:space:]]*Subject:[[:space:]]*//' | tr ',/' '\n\n' \
    | grep -qxF -- "CN=${TOUCHENV_EXPECTED_PUBLISHER}" \
    || { echo "$out" >&2; echo "the signer's CN is not '$TOUCHENV_EXPECTED_PUBLISHER': $f" >&2; exit 1; }
}

# ------------------------------------------------------------------ build, sign, verify, zip
echo "== touchenv $VERSION for Windows$([ "$UNSIGNED" = 1 ] && echo ' (UNSIGNED)')"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
mkdir -p "$DIST"
ZIPS=()
for arch in amd64:x64 arm64:arm64; do
  goarch=${arch%%:*} name=${arch#*:}
  mkdir -p "$BUILD/$name"
  # Exactly the workflow's build.
  (cd "$WIN" && GOOS=windows GOARCH=$goarch CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X $MODULE/internal/core.Version=$VERSION" -o "$BUILD/$name/touchenv.exe" .)
  LC_ALL=C grep -aqF -- "$VERSION" "$BUILD/$name/touchenv.exe" || { echo "$name: the version isn't in the exe" >&2; exit 1; }
  if [ "$UNSIGNED" = 0 ]; then
    sign "$BUILD/$name/touchenv.exe"
    verify "$BUILD/$name/touchenv.exe"
    echo "-- $name: signed, timestamped and verified ($TOUCHENV_EXPECTED_PUBLISHER)"
  fi
  cp "$ROOT/LICENSE" "$BUILD/$name/"
  suffix=""
  if [ "$UNSIGNED" = 1 ]; then suffix="-UNSIGNED"; fi # not $( [ … ] && … ): a false test would end the script (set -e)
  zip="touchenv-$VERSION-windows-$name$suffix.zip"
  rm -f "$DIST/$zip" "$DIST/$zip.sha256"
  (cd "$BUILD/$name" && zip -q -X "$DIST/$zip" touchenv.exe LICENSE)
  unzip -p "$DIST/$zip" touchenv.exe | cmp -s - "$BUILD/$name/touchenv.exe" \
    || { echo "$zip does not hold the verified touchenv.exe" >&2; exit 1; }
  (cd "$DIST" && shasum -a 256 "$zip" > "$zip.sha256")
  ZIPS+=("dist/$zip" "dist/$zip.sha256")
done
for f in "${ZIPS[@]}"; do case "$f" in *.sha256) cat "$ROOT/$f" ;; esac; done
echo "== done. Nothing was uploaded."
if [ "$UNSIGNED" = 1 ]; then
  echo "   UNSIGNED: for testing only, never attach these to a release."
  exit 0
fi
cat <<EOF

To attach them to the release (from $ROOT):

  gh release upload v$VERSION ${ZIPS[*]} --clobber
EOF
