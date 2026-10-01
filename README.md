# Python Security Toolkit

A compact defensive-security toolkit written in Python to demonstrate **secure automation, file-integrity monitoring, HTTP security review, IOC extraction, log analysis, testing, and CLI engineering**.

> Portfolio / learning project. The tools are intentionally narrow, auditable, and designed for systems and data you own or are authorized to assess.

## Included tools

| Command | Purpose |
|---|---|
| `hash` | Calculate SHA-256 / SHA-384 / SHA-512 file hashes |
| `integrity create` | Build a SHA-256 integrity manifest for a directory |
| `integrity verify` | Detect modified, missing, and unexpected files |
| `headers` | Review common HTTP response security headers for one URL |
| `iocs` | Extract common indicators from text or a file |
| `auth-log` | Summarize accepted/failed authentication events and source IPs |

## Why this repository exists

Security scripting is most useful when the automation is:

- easy to understand
- explicit about scope
- deterministic
- testable
- safe by default
- suitable for pipelines and repeatable workflows

This project therefore uses the Python standard library for runtime functionality and keeps third-party packages limited to development and quality checks.

## Installation

Requires Python 3.13+.

```bash
git clone https://github.com/EmilAlizada/python-security-toolkit.git
cd python-security-toolkit

python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
```

The CLI is then available as:

```text
sec-toolkit
```

## Usage

### Hash a file

```bash
sec-toolkit hash ./artifact.bin
sec-toolkit hash ./artifact.bin --algorithm sha512
```

### Create an integrity baseline

```bash
sec-toolkit integrity create ./important-data ./baseline.json
```

Verify it later:

```bash
sec-toolkit integrity verify ./important-data ./baseline.json
```

Example result:

```text
modified: config/settings.conf
missing:  keys/public.pem
unexpected: notes.tmp
```

### Review HTTP security headers

This command makes a request to **one explicitly supplied HTTP/HTTPS URL** and reports whether commonly expected response headers are present.

```bash
sec-toolkit headers https://example.com
```

Example categories:

```text
present: Content-Security-Policy
present: X-Content-Type-Options
missing: Permissions-Policy
```

It is not a crawler, port scanner, vulnerability exploit, or brute-force tool.

### Extract IOCs

```bash
sec-toolkit iocs ./incident-note.txt
```

Or:

```bash
sec-toolkit iocs --text "Observed 203.0.113.10 and deadbeef..."
```

The parser can identify:

- IPv4 / IPv6 addresses
- URLs
- domain names
- SHA-256 hashes

### Summarize authentication logs

```bash
sec-toolkit auth-log ./auth.log
```

The parser summarizes common Linux-style messages such as:

- `Failed password`
- `Accepted password`
- `Invalid user`

It also reports source IPs associated with failed events.

## Repository layout

```text
.
├── .github/
│   ├── dependabot.yml
│   └── workflows/ci.yml
├── docs/
│   ├── DESIGN.md
│   └── SECURITY_NOTES.md
├── src/security_toolkit/
│   ├── cli.py
│   ├── hashing.py
│   ├── headers.py
│   ├── integrity.py
│   ├── iocs.py
│   └── log_analysis.py
├── tests/
├── pyproject.toml
├── requirements-dev.txt
└── SECURITY.md
```

## Quality gates

Every push and pull request runs:

```text
Ruff
  -> mypy
  -> pytest
  -> Bandit SAST
  -> package build/import check
```

The repository includes tests for normal behavior and important edge cases such as:

- modified / missing / unexpected files
- unsupported hash algorithms
- unsafe URL schemes
- absent HTTP security headers
- invalid IP lookalikes
- repeated failed-login events

## Safety boundaries

This repository is defensive by design.

It does **not** include:

- credential attacks
- exploit delivery
- malware
- persistence
- destructive actions
- stealth features
- bulk internet scanning

Use the network-related functionality only against systems you own or are explicitly authorized to assess.

## Documentation

- [Design notes](docs/DESIGN.md)
- [Security notes](docs/SECURITY_NOTES.md)
- [Security policy](SECURITY.md)

## Roadmap

- [ ] JSON output mode for SIEM / automation workflows
- [ ] allow signed integrity manifests
- [ ] structured auth-log parser profiles
- [ ] additional IOC formats
- [ ] package release workflow
- [ ] SBOM generation for releases

## Author

**Emil Alizada**  
Cybersecurity · DevOps · Secure Backend Engineering
