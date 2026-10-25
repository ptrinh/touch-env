#!/bin/sh
# Builds touchenv.app, signs it and installs it:
#   ~/Applications/touchenv.app  +  ~/.local/bin/touchenv -> touchenv.app/Contents/MacOS/touchenv
#
# Needs an Apple Developer account: the keychain access group is a restricted entitlement, so the app must be
# signed with your Developer ID and carry a provisioning profile that grants it (see README, "Build it yourself").
#
#   TOUCHENV_TEAM_ID    your team ID, e.g. ABCDE12345
#   TOUCHENV_BUNDLE_ID  the App ID the profile was made for, e.g. com.example.touchenv
#   TOUCHENV_SIGN_ID    signing identity, e.g. "Developer ID Application: Your Name (ABCDE12345)"
#   TOUCHENV_PROFILE    path to the Developer ID provisioning profile for that App ID
#   TOUCHENV_APP_DIR    where touchenv.app goes (default ~/Applications)
#   TOUCHENV_BIN_DIR    where the touchenv link goes (default ~/.local/bin; empty to skip)
#
# The variables can also live in ./build.local (sourced if present, not in git).
set -e
cd "$(dirname "$0")"
[ -f build.local ] && . ./build.local
: "${TOUCHENV_TEAM_ID:?set TOUCHENV_TEAM_ID}" "${TOUCHENV_BUNDLE_ID:?set TOUCHENV_BUNDLE_ID}" "${TOUCHENV_SIGN_ID:?set TOUCHENV_SIGN_ID}" "${TOUCHENV_PROFILE:?set TOUCHENV_PROFILE}"
TOUCHENV_APP_DIR="${TOUCHENV_APP_DIR:-$HOME/Applications}"
TOUCHENV_BIN_DIR="${TOUCHENV_BIN_DIR-$HOME/.local/bin}"
version=$(sed -n 's/^let version = "\(.*\)"$/\1/p' touchenv.swift)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
app="$work/touchenv.app"
mkdir -p "$app/Contents/MacOS"
swiftc -O -target arm64-apple-macos13 touchenv.swift -o "$work/touchenv-arm64"
swiftc -O -target x86_64-apple-macos13 touchenv.swift -o "$work/touchenv-x86_64"
lipo -create "$work/touchenv-arm64" "$work/touchenv-x86_64" -output "$app/Contents/MacOS/touchenv"
cp "$TOUCHENV_PROFILE" "$app/Contents/embedded.provisionprofile"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>$TOUCHENV_BUNDLE_ID</string>
  <key>CFBundleName</key><string>touchenv</string>
  <key>CFBundleExecutable</key><string>touchenv</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleVersion</key><string>$version</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
</dict></plist>
PLIST
cat > "$work/touchenv.entitlements" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.application-identifier</key><string>$TOUCHENV_TEAM_ID.$TOUCHENV_BUNDLE_ID</string>
  <key>com.apple.developer.team-identifier</key><string>$TOUCHENV_TEAM_ID</string>
  <key>keychain-access-groups</key><array><string>$TOUCHENV_TEAM_ID.$TOUCHENV_BUNDLE_ID</string></array>
</dict></plist>
PLIST
codesign -f -s "$TOUCHENV_SIGN_ID" -o runtime --timestamp --entitlements "$work/touchenv.entitlements" "$app"

mkdir -p "$TOUCHENV_APP_DIR"
rm -rf "$TOUCHENV_APP_DIR/touchenv.app"
ditto "$app" "$TOUCHENV_APP_DIR/touchenv.app"
if [ -n "$TOUCHENV_BIN_DIR" ]; then
  mkdir -p "$TOUCHENV_BIN_DIR"
  ln -sf "$TOUCHENV_APP_DIR/touchenv.app/Contents/MacOS/touchenv" "$TOUCHENV_BIN_DIR/touchenv"
fi
echo "touchenv $version -> $TOUCHENV_APP_DIR/touchenv.app"
