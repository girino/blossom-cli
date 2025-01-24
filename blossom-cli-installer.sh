#!/bin/bash

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go first."
    exit 1
fi

# Create a directory for the project
echo "Creating directory for Blossom CLI..."
mkdir -p ~/blossom-cli
cd ~/blossom-cli

# Clone the repository
# echo "Cloning Blossom CLI repository..."
# git clone https://github.com/girino/blossom-cli.git .

# Download Go dependencies
echo "Downloading Go dependencies..."
go mod download

# Build the project
echo "Building Blossom CLI..."
go build -o blossom-cli .

# Make the binary executable
chmod +x blossom-cli

# Add to PATH (optional)
echo "Adding Blossom CLI to PATH..."
mkdir -p ~/bin
cp blossom-cli ~/bin/

# Update PATH in shell configuration if needed
if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
    echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
    echo "Please restart your shell or run 'source ~/.bashrc' to update PATH"
fi

# Print success message
echo "Blossom CLI has been successfully installed!"
echo "You can now use 'blossom-cli' from anywhere in your terminal"
echo "Example usage:"
echo "blossom-cli upload -server <server_url> -file <file_path> -privkey <private_key>"
