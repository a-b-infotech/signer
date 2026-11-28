#!/bin/bash
set -e

echo "=== Installing A B INFOTECH SIGNER OFFLINE (macOS) ==="

# 1. Install Root Certificate to System Keychain
if [ -f "ab_infotech_ca_cert.cer" ]; then
  echo "Installing Security Certificate to System Keychain..."
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ab_infotech_ca_cert.cer || true
fi

# 2. Copy App to /Applications
if [ -d "Abinfo_Signer_Offline.app" ]; then
  echo "Installing to /Applications..."
  sudo rm -rf "/Applications/Abinfo_Signer_Offline.app"
  sudo cp -R "Abinfo_Signer_Offline.app" /Applications/
fi

# 3. Install macOS .dylib token drivers only (no .dll, no .so)
if [ -d "drivers/macos" ]; then
  echo "Installing token drivers..."
  sudo mkdir -p "/Applications/Abinfo_Signer_Offline.app/Contents/MacOS/drivers/macos"
  sudo cp -f drivers/macos/*.dylib "/Applications/Abinfo_Signer_Offline.app/Contents/MacOS/drivers/macos/" 2>/dev/null || true
  sudo mkdir -p "/usr/local/lib"
  sudo cp -f drivers/macos/*.dylib "/usr/local/lib/" 2>/dev/null || true
elif [ -d "drivers" ]; then
  echo "Installing token drivers..."
  sudo mkdir -p "/Applications/Abinfo_Signer_Offline.app/Contents/MacOS/drivers/macos"
  sudo cp -f drivers/*.dylib "/Applications/Abinfo_Signer_Offline.app/Contents/MacOS/drivers/macos/" 2>/dev/null || true
  sudo mkdir -p "/usr/local/lib"
  sudo cp -f drivers/*.dylib "/usr/local/lib/" 2>/dev/null || true
fi

# 3. Add to Login Items for autostart
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Applications/Abinfo_Signer_Offline.app", hidden:true}' 2>/dev/null || true

echo "✓ A B INFOTECH SIGNER OFFLINE installed successfully!"
echo "You can open it from /Applications or Launchpad."
