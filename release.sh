#!/bin/sh
# Maintainer only: builds touchenv.app into dist/, notarizes and staples it, and zips it for a GitHub release.
#   NOTARY_PROFILE  notarytool keychain profile (xcrun notarytool store-credentials); only while the screen is
#                   unlocked. Or, for a locked screen too, an App Store Connect API key: NOTARY_KEY / NOTARY_KEY_ID /
#                   NOTARY_ISSUER, or ASC_KEY_PATH / ASC_KEY_ID / ASC_ISSUER_ID, e.g. after touchenv grant --for 2h ASC_KEY_PATH:
#     touchenv run --intent "release" ASC_KEY_PATH:file -- ./release.sh
# Only the Mac files in dist/ are replaced: Windows zips made before by windows/release.sh stay.
# Windows builds are not made here: publishing the GitHub release (tag v<version>) starts .github/workflows/windows.yml,
# which tests them and attaches touchenv-<version>-windows-x64.zip and -arm64.zip (+ .sha256) to the same release.
set -e
cd "$(dirname "$0")"
# notarize submits a zip and waits; it fails unless Apple accepted it. With
# NOTARY_PROFILE it signs in with that notarytool keychain profile, which only
# works while the screen is unlocked. Without it, with an App Store Connect API
# key: NOTARY_KEY (the .p8 file), NOTARY_KEY_ID and NOTARY_ISSUER, or else
# ASC_KEY_PATH, ASC_KEY_ID and ASC_ISSUER_ID. Run that way under touchenv
# (touchenv run --intent "release" ASC_KEY_PATH:file -- <this script> ...), after
# a touchenv grant for ASC_KEY_PATH, a release also goes through while the
# screen is locked.
notarize() {
	if [ -n "${NOTARY_PROFILE:-}" ]; then
		result=$(xcrun notarytool submit "$1" --keychain-profile "$NOTARY_PROFILE" --wait 2>&1) || { echo "$result" >&2; return 1; }
	else
		key=${NOTARY_KEY:-${ASC_KEY_PATH:-}} key_id=${NOTARY_KEY_ID:-${ASC_KEY_ID:-}} issuer=${NOTARY_ISSUER:-${ASC_ISSUER_ID:-}}
		if [ -z "$key" ] || [ -z "$key_id" ] || [ -z "$issuer" ]; then
			echo "notarize: set NOTARY_PROFILE, or an App Store Connect API key (NOTARY_KEY, NOTARY_KEY_ID, NOTARY_ISSUER)" >&2
			return 1
		fi
		result=$(xcrun notarytool submit "$1" --key "$key" --key-id "$key_id" --issuer "$issuer" --wait 2>&1) || { echo "$result" >&2; return 1; }
	fi
	echo "$result"
	echo "$result" | grep -q "status: Accepted" || { echo "notarize: $1 was not accepted" >&2; return 1; }
}

version=$(sed -n 's/^let version = "\(.*\)"$/\1/p' touchenv.swift)
rm -rf dist/touchenv.app dist/notarize.zip dist/touchenv-*-macos.zip dist/touchenv-*-macos.zip.sha256 && mkdir -p dist
TOUCHENV_APP_DIR="$PWD/dist" TOUCHENV_BIN_DIR="" ./build.sh
ditto -c -k --keepParent dist/touchenv.app dist/notarize.zip
notarize dist/notarize.zip
xcrun stapler staple dist/touchenv.app
rm dist/notarize.zip
ditto -c -k --keepParent dist/touchenv.app "dist/touchenv-$version-macos.zip"
(cd dist && shasum -a 256 "touchenv-$version-macos.zip" > "touchenv-$version-macos.zip.sha256")
spctl -a -vv -t exec dist/touchenv.app
echo "dist/touchenv-$version-macos.zip"
