#!/usr/bin/env bash

# Ensure the entire script has been downloaded
{
  # Expected environment variables
  VENDOR=bright
  PRODUCT_NAME=$VENDOR-cli
  INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
  PROFILE_FILES=("$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zshrc" "$HOME/.profile")

  # Download an executable
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  DOWNLOAD_URL=https://github.com/BrightSec/$PRODUCT_NAME/releases/latest/download/$PRODUCT_NAME

  if [[ "$OS" == "linux-gnu"* ]]; then
    DOWNLOAD_URL+="-linux-x64"
  elif [[ "$OSTYPE" == "darwin"* ]]; then
    DOWNLOAD_URL+="-macos-x64"
  else
    echo "Error: unknown OS type."
    exit 1
  fi

  # Create an installation folder if not exist
  if [ ! -d "$INSTALL_DIR" ] ; then
    echo "Creating $INSTALL_DIR folder..."
    mkdir -p "$INSTALL_DIR"
  fi

  # Remove the original executable if exists
  if [ -f "$INSTALL_DIR/$PRODUCT_NAME" ]; then
    echo "$PRODUCT_NAME already exists in $INSTALL_DIR. Removing the existing version."
    rm -f "$INSTALL_DIR/$PRODUCT_NAME"
  fi

  echo "Installing $PRODUCT_NAME to $INSTALL_DIR..."
  if command -v curl >/dev/null 2>&1; then
      curl -fsSL "$DOWNLOAD_URL" > "$INSTALL_DIR/$PRODUCT_NAME"
  elif command -v wget >/dev/null 2>&1; then
      wget -qO- "$DOWNLOAD_URL" > "$INSTALL_DIR/$PRODUCT_NAME"
  else
      echo "Error: curl or wget not found."
      exit 1
  fi

  echo "Granting permission to execute $INSTALL_DIR/$PRODUCT_NAME..."
  chmod +x "$INSTALL_DIR/$PRODUCT_NAME"

  echo "Patching PATH env variable..."
  # Loop over profile files and update PATH if they exist
  for PROFILE_FILE in "${PROFILE_FILES[@]}"
  do
      if [ -f "$PROFILE_FILE" ]; then
          if ! grep -q "$INSTALL_DIR" "$PROFILE_FILE"; then
              echo -n "export PATH=\"${INSTALL_DIR}:\$PATH\"" >> "$PROFILE_FILE"
              source "$PROFILE_FILE" > /dev/null 2>&1
              # change the PATH right now
              PATH="$PATH:$HOME/.local/bin"
          fi
      fi
  done
}
