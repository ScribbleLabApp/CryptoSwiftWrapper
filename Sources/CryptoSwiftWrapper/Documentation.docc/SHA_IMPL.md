# SHA Algorithm Implementation

Implementing SHA hashing algorithm functions in both C and Swift

## Overview

The SHA-256 and SHA-512 algorithms are implemented in C within this package to provide robust cryptographic hashing functionalities. These algorithms ensure data integrity and security through their respective 256-bit and 512-bit hash outputs.

### Key Components

- **Constants and Macros:** The implementations utilize predefined constants and macros for bitwise operations and block processing, enhancing efficiency and clarity in the code.
- **Message Schedule Processing:** Both algorithms employ a message schedule structure (`SHA256_Message_Schedule` and `SHA512_Message_Schedule`) to manage data flow and perform iterative hash computations over data blocks.

- **Compression Function:** The `sha256_compress` and `sha512_compress` functions handle the core compression steps, combining message schedule data with current state values to produce updated hash values.**

- **Error Handling:** Custom error codes (`SHA512_NULL_INPUT`, `SHA512_NULL_OUTPUT`, `SHA512_MEMORY_ERROR`, `SHA512_INVALID_LENGTH`, etc.) are defined to manage exceptional scenarios like null inputs, memory allocation failures, and invalid data lengths.

These SHA implementations are integrated into larger systems requiring secure hash computations, such as cryptographic protocols, digital signatures, and data integrity verification mechanisms. They provide essential tools for ensuring data confidentiality and authenticity in software applications.

### Background
SHA-256 is a widely-used cryptographic hash function that generates a 256-bit hash value, ensuring data integrity and security in various applications. Implemented efficiently in C, it employs bitwise operations and constants to process data blocks, providing robust hashing capabilities.

Whereas SHA-256 is more often used SHA-512 is a stronger variant of SHA-256, producing a 512-bit hash value. Its implementation in C utilizes similar principles but operates on larger data blocks, enhancing security and resistance to cryptographic attacks. It supports applications requiring higher security standards and larger hash outputs.

@Comment {
### Implementation

@TabNavigator {
    @Tab("Swift") {}
    @Tab("C") {}
}
}
