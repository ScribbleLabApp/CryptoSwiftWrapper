#!/bin/bash

##===------------------------------------------------------------------------------===##
##
## This source file is part of the CryptoSwiftWrapper open source project
##
## Copyright (c) 2024 ScribbleLabApp - All rights reserved. and the ScribbleLab
## project authors. Licensed under Apache License v2.0 with Runtime Library Exception
##
## You may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##      http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##
## See LICENSE for license information
##
## SPDX-License-Identifier: Apache-2.0
##
##===------------------------------------------------------------------------------===##

GREEN='\033[1;32m'
RED='\033[0;31m'
ORANGE='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

if [[ "$TERM" != "xterm-256color" ]] && ! command -v tput &> /dev/null; then
    echo "Warning: ANSI escape codes not supported. Falling back to basic text formatting."
    bold() { echo -e "${BOLD}$1${RESET}"; }
    red() { echo -e "${RED}$1${RESET}"; }
    green() { echo -e "${GREEN}$1${RESET}"; }
    orange() { echo -e "${ORANGE}$1${RESET}"; }
    reset() { echo -e "$1"; }
else
    bold() { tput bold; echo -e "$1"; tput sgr0; }
    red() { tput setaf 1; echo -e "$1"; tput sgr0; }
    green() { tput setaf 2; tput bold; echo -e "$1"; tput sgr0; }
    orange() { tput setaf 3; echo -e "$1"; tput sgr0; }
    reset() { tput sgr0; echo -e "$1"; }
fi

bold "${BOLD}Welcome to the ScribbleLabApp CryptoSwiftWrapper build script${BOLD}"
echo ""
echo "Version: 0.1.0-beta (3)"
echo "Copyright (c) 2024 - ScribbleLabApp. All rights reserved."
echo ""
orange "${BOLD}[Warning]: CryptoSwiftWrapper & CCrypto are in development - Unknown behaviour may appear${RESET}"

printUsage() {
    echo ""
    bold "${BOLD}Usage:${RESET}"
    orange "./build_script.sh    -some_flag"
    bold "                     ${BOLD}-c, --complete${RESET}        Builds the complete project"
    bold "                     ${BOLD}-libc, --libc${RESET}         Builds only CCrypto (standalone C)"
    bold "                     ${BOLD}-w, --wrapper${RESET}         Builds only CryptoSwiftWrapper and _cyfn"
    bold "                     ${BOLD}-h, --help${RESET}            Shows this message"
}

checkTools() {
    if ! command -v cmake &> /dev/null; then
    red "Error: cmake is not installed."
    exit 1
    fi
    
    if ! command -v make &> /dev/null; then
    red "Error: make is not installed."
    exit 1
    fi
}

buildCompleteProj() {
    orange "Checking Requirements..."
    checkTools
    
    echo "Warning: CCrypto is not ready yet"
}

buildCCryptoOnly() {
    orange "Checking Requirements..."
    checkTools
    
    echo "Warning: CCrypto is not ready yet"
}

buildWrapper() {
    orange "Checking Requirements..."
    checkTools

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
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -c|--complete) buildCompleteProj; exit 0 ;;
        -libc|--libc) buildCCryptoOnly; exit 0 ;;
        -w|--wrapper) buildWrapper; exit 0 ;;
        -h|--help) printUsage; exit 0 ;;
        *) red "Unknown flag: $1"; printUsage; exit 1 ;;
    esac
    shift
done

printUsage
