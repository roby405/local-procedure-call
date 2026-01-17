
### Implemented Bonus: Payload Security Checks

The dispatcher scans each call payload and blocks suspicious content before forwarding it to a
service. It looks for simple shellcode indicators like /bin/sh, /bin/bash, int 0x80 or syscall
byte sequences, and NOP sleds. When blocked, the dispatcher replies with the same function name
and a single argument: SECURITY_BLOCKED.

#### How to test (after checker passes)

1. Start the dispatcher and service (same steps as the checker).
2. In tests/client-manager.cpp, set arg1 to /bin/sh.
3. Rebuild tests (make in the tests folder).
4. Run the client with 10 or more clients so it actually sends arguments.
5. You should see SECURITY_BLOCKED in the client output.

After testing, revert arg1 to arg1 so the checker stays clean.

### Implemented Bonus: Protocol Extension (Optional Fields)

The dispatcher accepts an optional extension appended to the install payload.
If present, it reads 1 byte of flags and a 4‑byte checksum (big-endian) of the
access path (FNV-1a 32-bit). If absent, it behaves exactly like the base protocol.
This keeps compatibility with the checker while allowing extra robustness data.

#### How to test (after the checker passes)

1. In tests/service.cpp, after writing the normal install payload, append:
    - 1 byte flags (e.g., 0x01)
    - 4 bytes checksum = htobe32(FNV-1a("/hello"))
2. Rebuild tests (make in the tests folder).
3. Start dispatcher and service.
4. You should see no warnings; if checksum is wrong, dispatcher logs a mismatch.

After testing, revert tests/service.cpp to keep the checker clean.
