#!/bin/sh
# Maintainer only: builds touchenv.app into dist/, notarizes and staples it, and zips it for a GitHub release.
#   NOTARY_PROFILE  notarytool keychain profile (xcrun notarytool store-credentials)
set -e
cd "$(dirname "$0")"
: "${NOTARY_PROFILE:?set NOTARY_PROFILE}"
version=$(sed -n 's/^let version = "\(.*\)"$/\1/p' touchenv.swift)
rm -rf dist && mkdir dist
TOUCHENV_APP_DIR="$PWD/dist" TOUCHENV_BIN_DIR="" ./build.sh
ditto -c -k --keepParent dist/touchenv.app dist/notarize.zip
xcrun notarytool submit dist/notarize.zip --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple dist/touchenv.app
rm dist/notarize.zip
ditto -c -k --keepParent dist/touchenv.app "dist/touchenv-$version-macos.zip"
(cd dist && shasum -a 256 "touchenv-$version-macos.zip" > "touchenv-$version-macos.zip.sha256")
spctl -a -vv -t exec dist/touchenv.app
echo "dist/touchenv-$version-macos.zip"
