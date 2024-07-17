##===----------------------------------------------------------------------===##
##
## This source file is part of the CryptoSwiftWrapper open source project
##
## Copyright (c) 2024 ScribbleLabApp
## Copyright (c) 2021-2024 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE for license information
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

cmake_minimum_required(VERSION 3.15.1)
project(CryptoSwiftWrapper)

# Set paths
set(SWIFT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Sources/CryptoSwiftWrapper)
set(C_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Sources/_cyfn)

# Set include directories
include_directories(
    ${SWIFT_SRC_DIR}/include
    ${C_SRC_DIR}
)

# Define the Swift target name
set(SWIFT_TARGET_NAME CryptoSwiftWrapper)

# Find Swift and set its compiler path
find_program(SWIFT_EXECUTABLE swift)
if(NOT SWIFT_EXECUTABLE)
    message(FATAL_ERROR "Swift compiler not found!")
endif()

# Add SwiftPM as an ExternalProject
include(ExternalProject)

ExternalProject_Add(${SWIFT_TARGET_NAME}_External
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/${SWIFT_TARGET_NAME}-prefix
    SOURCE_DIR ${SWIFT_SRC_DIR}
    BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/${SWIFT_TARGET_NAME}-build
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${SWIFT_EXECUTABLE} build --package-path ${SWIFT_SRC_DIR}
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${SWIFT_TARGET_NAME}-build/*.dylib
)

# Dummy target for header-only C library
add_library(cyfn INTERFACE)
target_include_directories(cyfn INTERFACE ${C_SRC_DIR})

# Create custom target to build the C library
add_custom_target(CLibrary DEPENDS cyfn)
add_dependencies(CLibrary ${SWIFT_TARGET_NAME}_External)

# Optional: Install targets
# Since cyfn is a header-only library, no need to install anything

# Clean command
add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/clean-all.cmake
)
