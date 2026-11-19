# Rule reference

All rules are line-based heuristics. Confidence is a qualitative review hint, not a probability. Language support is limited to the listed patterns, not complete language coverage.

| ID | Check | Severity | Confidence | CWE | File types | Remediation |
|---|---|---|---|---|---|---|
| DTG001 | Dynamic code execution | high | medium | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | js, mjs, cjs, ts, jsx, tsx, py | Replace dynamic execution with a constrained parser or an explicit operation map. |
| DTG002 | HTML injection sink | high | medium | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | js, mjs, ts, jsx, tsx, html | Use textContent for text. For necessary rich HTML, use a maintained sanitizer and a restrictive CSP. |
| DTG003 | Shell command execution | high | medium | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | py, js, mjs, ts | Use an allowlisted executable and an argument array with shell disabled. Validate arguments. |
| DTG004 | SQL query interpolation | high | medium | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | py, js, mjs, ts | Use driver-bound query parameters. Do not interpolate values or identifiers from requests. |
| DTG005 | TLS certificate validation disabled | high | high | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | py, js, mjs, ts, json, yaml, yml | Enable certificate and hostname validation. Configure a trusted CA for private services. |
| DTG006 | Unsafe Python deserialization | high | medium | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | py | Use JSON with schema validation or yaml.safe_load. Never unpickle untrusted data. |
| DTG007 | Weak digest for security review | medium | low | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | py, js, mjs, ts | Review purpose. For passwords use Argon2id/scrypt; for integrity use SHA-256 or stronger. Non-security checksums may be acceptable. |
| DTG008 | Development debugger enabled | high | medium | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | py, js, mjs, ts, json | Disable interactive debugging in production. Keep error details in access-controlled logs. |
| DTG009 | Literal credential assignment | high | medium | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | py, js, mjs, ts, json, yaml, yml, env | Remove the literal, rotate any real exposed credential, and load it from a secret manager. Reports omit source values. |
| DTG010 | Private key material | critical | high | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | * | Remove and rotate this key; investigate its history and affected access. |
| DTG011 | GitHub credential pattern | critical | high | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | * | Revoke the credential, investigate usage, and remove it from current code and history. |
| DTG012 | Unsafe C string or formatting API | high | medium | [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | c, h, cpp, hpp, cc | Use bounds-aware APIs and explicit lengths; test boundary conditions with sanitizers. |
| DTG013 | Workflow has broad write permission | high | high | [CWE-269](https://cwe.mitre.org/data/definitions/269.html) | yml, yaml | Set contents: read by default; grant only the required job-scoped permissions. |
| DTG014 | Workflow executes expression in script | high | low | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | yml, yaml | For shell scripts, pass untrusted event text through an environment variable and quote it. Review context: expressions in metadata are not executable. |
| DTG015 | Workflow action is not pinned to a commit | medium | medium | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | yml, yaml | Pin third-party actions to an audited full commit SHA and use Dependabot to review updates. |
| DTG016 | Remote script piped to shell | high | medium | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | sh, bash, yml, yaml, dockerfile | Fetch a pinned artifact and verify its signature or checksum before execution. |
| DTG017 | Wildcard CORS configuration | medium | low | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | py, js, mjs, ts, json | Restrict origins for private APIs; review credential handling. Public non-credentialed APIs may intentionally use wildcard CORS. |
| DTG018 | Disabled container isolation | high | medium | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | yml, yaml, sh, bash | Avoid privileged mode and Docker socket mounts. Use rootless containers and scoped capabilities. |
| DTG019 | Mutable container image tag | medium | low | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | dockerfile | Pin the base image by sha256 digest, review updates and scan image dependencies. |

The C/C++ rule only flags selected unsafe string APIs. Workflow expression checks can flag harmless metadata uses; review the execution context. Literal credentials may be synthetic test data. MD5/SHA-1 may be non-security checksums. Wildcard CORS can be appropriate for public non-credentialed resources. Mutable image tags and non-SHA action pins are supply-chain review findings, not known CVEs.

Missing features: AST parsing, cross-file and multiline data flow, aliases, authorization logic, dependency advisory queries, malicious package detection and runtime blocking. Full-line comments beginning with `//`, `#` or `*` are skipped, which can also hide relevant content in unusual formats.
