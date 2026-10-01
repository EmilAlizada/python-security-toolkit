# Design Notes

## Goals

The toolkit is intentionally designed around small, auditable operations rather than broad "all-in-one hacking" functionality.

Each module should:

1. solve one defensive problem
2. expose a pure function where practical
3. separate analysis logic from CLI formatting
4. validate input early
5. provide predictable exit codes
6. be covered by tests

## Module boundaries

### hashing

Provides cryptographic file hashing using SHA-2 algorithms.

MD5 and SHA-1 are intentionally not offered as normal CLI choices because the project is designed around modern integrity workflows.

### integrity

Creates and verifies JSON manifests containing relative paths and SHA-256 digests.

Verification reports three independent states:

- modified
- missing
- unexpected

### headers

Makes a request to exactly one caller-supplied HTTP/HTTPS URL.

The network function validates the URL scheme before opening it. Header analysis itself is a pure function and can be tested without network access.

The result is intentionally informational. Header presence alone does not prove that an application is secure.

### iocs

Extracts common indicator-shaped values from unstructured text.

IP candidates are passed through Python's `ipaddress` validation rather than trusting a regex alone.

### log_analysis

Parses a deliberately small set of common Linux/SSH authentication messages.

The module is not positioned as a universal log parser. Its narrow scope keeps the behavior explicit and testable.

## Exit-code behavior

- `0`: requested operation completed successfully
- `1`: analysis completed but found a condition worth attention
- `2`: invalid input or operational error

For example, integrity verification returns `1` when drift is detected.

## Runtime dependencies

The toolkit uses the Python standard library at runtime.

Development dependencies are reserved for:

- tests
- linting
- static type checking
- SAST
- package builds

This keeps the runtime attack surface and dependency footprint small.
