#!/bin/bash

GREEN='\033[1;32m'   # Change to bold green
RED='\033[0;31m'
ORANGE='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

# Check if terminal supports ANSI escape codes
if [[ "$TERM" != "xterm-256color" ]] && ! command -v tput &> /dev/null; then
    echo "Warning: ANSI escape codes not supported. Falling back to basic text formatting."
    # Define basic text formatting functions
    bold() { echo -e "${BOLD}$1${RESET}"; }
    red() { echo -e "${RED}$1${RESET}"; }
    green() { echo -e "${GREEN}$1${RESET}"; }
    orange() { echo -e "${ORANGE}$1${RESET}"; }
    reset() { echo -e "$1"; }
else
    # Define functions using tput for terminal text formatting
    bold() { tput bold; echo -e "$1"; tput sgr0; }
    red() { tput setaf 1; echo -e "$1"; tput sgr0; }
    green() { tput setaf 2; tput bold; echo -e "$1"; tput sgr0; }  # Modify green to be bold
    orange() { tput setaf 3; echo -e "$1"; tput sgr0; }
    reset() { tput sgr0; echo -e "$1"; }
fi

bold "${BOLD}Welcome to the ScribbleLabApp CryptoSwiftWrapper build script${BOLD}"
echo ""
echo "Version: 0.1.0-beta (1)"
echo "Copyright (c) 2024 - ScribbleLabApp. All rights reserved."
echo ""

# Check for required tools
if ! command -v cmake &> /dev/null; then
    red "Error: cmake is not installed."
    exit 1
fi

if ! command -v make &> /dev/null; then
    red "Error: make is not installed."
    exit 1
fi

# Build process
orange "Creating build folder..."
mkdir -p build
cd build

orange "Configuring cmake..."
echo ""
cmake ..

orange "Building project..."
echo ""
make .

echo ""
green "${GREEN}[Success]: Build completed successfully.${RESET}"
