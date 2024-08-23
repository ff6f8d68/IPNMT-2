#!/bin/bash

# Set variables
REPO_URL="https://github.com/yourusername/yourrepository.git"
CLONE_DIR="/tmp/yourrepository"
INSTALL_DIR="/usr/local/yourrepository"

# Exit on any error
set -e

# Print commands and their arguments as they are executed
set -x

# Fetch the latest version of the repository
if [ -d "$CLONE_DIR" ]; then
  echo "Repository already cloned. Pulling latest changes."
  cd "$CLONE_DIR" && git pull
else
  echo "Cloning repository..."
  git clone "$REPO_URL" "$CLONE_DIR"
fi

# Ensure the install directory exists
echo "Creating installation directory if it doesn't exist."
mkdir -p "$INSTALL_DIR"

# Copy all files from the cloned repo to the install directory
echo "Copying files to $INSTALL_DIR"
cp -r "$CLONE_DIR/"* "$INSTALL_DIR/"

# Set execute permissions for all scripts in the install directory
echo "Setting execute permissions for scripts in $INSTALL_DIR"
find "$INSTALL_DIR" -type f -name "*.sh" -exec chmod +x {} \;

echo "Installation complete. You can now run the scripts from $INSTALL_DIR."
