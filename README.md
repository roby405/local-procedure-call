# High-Performance Local Procedure Call (LPC) System

A C++17-based communication daemon designed for high-performance, networkless Inter-Process Communication (IPC). This system allows local processes (clients and services) to exchange information and execute remote procedures via Unix Named Pipes (FIFOs), similar to gRPC but optimized for single-host environments.

## Key Features

* **Custom Binary Protocol:** Implemented a robust communication protocol with Big-Endian/Host byte order conversion to ensure data integrity across entity handshakes.
* **High Concurrency:** Utilizes an asynchronous, multi-threaded model (Detached Threads) to manage multiple simultaneous client-service connections without blocking the main event loop.
* **I/O Optimization:** Leveraged Scatter/Gather I/O (writev) and iovec structures to route large binary payloads between pipes with minimal system call overhead.
* **Self-Healing Resource Management:** Automated creation and cleanup of FIFO pipes in controlled directories (.dispatcher and .pipes), including symlink fallbacks for environments with restricted permissions.
* **System Integrity:** Handles system-level constraints such as file descriptor table limits and atomic pipe creation with retry logic.

## Implemented Security & Extensions (Bonus)

Beyond the core requirements, this implementation includes advanced security and robustness features:

### 1. Payload Security Inspection
The dispatcher acts as a security proxy, scanning call payloads for malicious patterns before forwarding them to services.
* **Signature Detection:** Identifies shellcode indicators like /bin/sh, /bin/bash, and NOP sleds (0x90).
* **Syscall Blocking:** Detects byte sequences for int 0x80 or syscall to prevent unauthorized kernel access.
* **Automatic Quarantine:** Blocks suspicious requests and notifies the client with a SECURITY_BLOCKED status.

### 2. Protocol Extension (Integrity Verification)
Added a custom extension to the install payload for increased robustness:
* **Checksum Verification:** Utilizes the FNV-1a 32-bit hashing algorithm to verify the checksum of service access paths.
* **Flags & Metadata:** Supports a 1-byte flag system for future-proofing protocol features while maintaining backward compatibility.

## Architecture

The Dispatcher acts as the central orchestration layer:
1.  **Service Registry:** Services register via InstallRequestHeader, exposing an access path.
2.  **Connection Handshake:** Clients request access to a path; the dispatcher creates unique session pipes (call_n and return_n).
3.  **Procedure Routing:** The dispatcher captures, sanitizes, and proxies data between the client and the service.

## Tech Stack
* **Language:** C++17
* **Operating System:** Linux (Unix System Programming)
* **I/O:** POSIX Named Pipes (FIFOs), writev, ioctl
* **Synchronization:** C++ Mutex, Detached Threads

## How to Run

1.  **Build the Project:**
    ```bash
    make
    ```
2.  **Start the Dispatcher:**
    ```bash
    ./dispatcher
    ```
3.  **Run Tests:**
    Navigate to the `checker/` directory and execute `./run_tests.sh`.

---
**Developers:** 
- Baran Denis-Constantin
- Epure Roberto-Constantin
