# Security Notes

## HTTP header analysis limitations

Security headers are one layer of browser-facing defense.

A "present" result does not prove that the header value is correct for a specific application, and a missing legacy header may be mitigated by a stronger modern control.

The tool therefore reports observations rather than producing a security score.

## Integrity limitations

A local integrity manifest can detect drift only when the baseline itself is trustworthy.

If an attacker can modify both the protected files and the manifest, verification can be bypassed.

Future work may add signed manifests so the baseline can be authenticated independently.

## IOC extraction limitations

Indicator extraction is pattern recognition, not threat attribution.

A value matching an IP address, domain, URL, or hash format should be treated as an observation requiring context—not proof of maliciousness.

## Authentication-log limitations

The parser recognizes selected Linux/SSH-style strings.

Different operating systems, authentication stacks, localization, or custom logging formats may require dedicated parsers.

## Network safety

The only network-capable command is `headers`.

It makes a request to one explicit HTTP/HTTPS URL supplied by the user. It does not crawl links, enumerate hosts, scan ports, brute-force credentials, or attempt exploitation.
