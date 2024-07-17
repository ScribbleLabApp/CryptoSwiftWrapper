# CYErrors

Defines error codes used by the CryptoSwiftWrapper module to indicate various types of failures during cryptographic operations.

## Overview

The CYErrors constants provide a standardized way to handle errors encountered during key generation, encryption, and decryption operations. These error codes help identify the specific issue that occurred, allowing for better debugging and error handling.

### Error Codes

#### `CY_ERR_GENKEY` (-1)

Error code indicating key generation failure.

#### `CY_ERR_ENCR` (-2)

Error code indicating encryption failure.

#### `CY_ERR_DECR` (-3)

Error code indicating decryption failure.

#### `CY_ERR_INIT` (-4)

Error code indicating initialization failure.

#### `CY_ERR_SHA256_NULL_PTR` (-6)

Error code indicating a null pointer error in SHA256 operations.

#### `CY_ERR_SHA256_INVALID_LEN` (-7)

Error code indicating an invalid length error in SHA256 operations.

#### `SHA512_NULL_INPUT` (-8)

Error code indicating null input parameter in SHA512 operations.

#### `SHA512_NULL_OUTPUT` (-9)

Error code indicating null output parameter in SHA512 operations.

#### `SHA512_MEMORY_ERROR` (-10)

Error code indicating memory allocation failure in SHA512 operations.

#### `SHA512_INVALID_LENGTH` (-11)

Error code indicating invalid input length in SHA512 operations.
