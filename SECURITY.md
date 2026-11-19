# Security policy

Version 1.x is supported. Report a vulnerability privately using GitHub's **Report a vulnerability** button in the Security tab. If unavailable, use contato@brunnodev.store with a minimal reproduction and affected version. Do not include credentials, private repository content or personal data in public issues.

The scanner reads source as text. It does not execute scanned projects, install their dependencies, make network requests, or apply fixes. The Action invokes the bundled CLI with an argument array and no shell. Symlinks are skipped; output paths are restricted inside the workspace and must not overwrite existing files. Treat repository configuration and exclusions as security-relevant input and review changes.

## Boundaries

- Pattern matching can miss aliases, multiline constructs, obfuscation, authorization flaws and context-dependent bugs. Benign strings can match. No taint analysis, AST parsing, dependency CVE data, malware detection, network filtering or intrusion prevention.
- Run on a stable checkout. Filesystem checks are not a sandbox against a concurrently mutating malicious filesystem. The CLI is intended to run with the permissions you ordinarily give source-analysis tools.
- SARIF/JSON omit source values, but filenames, rule IDs and locations remain. Keep reports private when their metadata is sensitive.
- `.devthreat.json` and baselines can hide findings; review them. A successful scan does not certify unscanned or ignored content.
- Browser JSON/URL/ID helpers address narrow boundaries. The URL helper only validates strings; it does not stop redirects or DNS rebinding in a server-side fetcher. Enforce egress policy, DNS/IP checks and redirect validation separately. JSON key checks are top-level only; use a schema and reject unknown nested shapes before merges.
- Educational source is inert. Use third-party security testing tools only on systems you own or have explicit authorization to assess. Preserve evidence and never use incident response as a reason to erase logs.
