<div align="center">

<img src="site/icon.svg" width="76" alt="DevThreat Guard shield">

# DevThreat Guard

**Find the risk. Understand the cause. Fix with evidence.**

Local-first security checks, reproducible secure coding labs, and a defense academy for developers.

[![Verify](https://github.com/brunnojob/devthreat-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/brunnojob/devthreat-guard/actions/workflows/ci.yml)
[![Pages](https://github.com/brunnojob/devthreat-guard/actions/workflows/pages.yml/badge.svg)](https://brunnojob.github.io/devthreat-guard/)
![MIT](https://img.shields.io/badge/license-MIT-b4f272)
![Dependencies](https://img.shields.io/badge/runtime_dependencies-0-b4f272)

[Open the lab](https://brunnojob.github.io/devthreat-guard/) · [Rules & limitations](docs/RULES.md) · [Research](docs/RESEARCH.md) · [Contribute](CONTRIBUTING.md)

</div>

Security reports often stop at an alert. Developers still need to understand the cause, choose a correction, and verify the behavior. DevThreat Guard connects these steps: **local pattern check → explanation and CWE → remediation guidance → regression test**.

- **19 explainable checks** for selected JavaScript/TypeScript, Python, C/C++, Docker and GitHub Actions patterns.
- **Private browser workbench:** paste or import a file; scan locally; filter findings; export JSON or SARIF. Scanned code is never executed or sent to a server.
- **CLI and GitHub Action:** severity gates, coverage accounting, exclusions, baselines, and text/JSON/Markdown/SARIF reports. No dependencies, API keys, AI service, or installation step in CI.
- **Evidence-based learning:** six PT-BR/EN modules, quizzes with local progress, vulnerable/fixed examples and a defensive tool catalog.
- **Small defensive helpers:** bounded JSON object parsing, exact HTTPS origin checks, numeric IDs and DOM text rendering. Helpers must be integrated at the correct application boundary; importing them does not secure an application automatically.

> This is a transparent heuristic scanner, not a general vulnerability detector, runtime firewall, CVE scanner or NIST certification. Zero findings means no matching patterns in checked files, not zero vulnerabilities. Findings require human review. There is no measured real-world precision or recall claim.

## Quick start

Requires Node.js **22+** (Action uses Node 24). No npm install required.

```sh
git clone https://github.com/brunnojob/devthreat-guard.git
cd devthreat-guard
node bin/devthreat-guard.mjs /path/to/your/project
node bin/devthreat-guard.mjs /path/to/your/project --format sarif --output report.sarif
npm test
python3 -m unittest discover -s test -p 'test_*.py'
npm run demo
```

CLI exit codes: `0` below configured threshold, `1` findings at/above threshold, `2` configuration/read/coverage errors or no supported files. Default gate is `high`; `--fail-on none` records findings without blocking but still reports operational errors. Scans skip symlinks, binaries, files larger than 1 MiB and known generated/vendor directories. Coverage lists every skip and read error. Unscanned files can still be vulnerable.

## Use in a workflow

```yaml
name: Security review
on: [push, pull_request]
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - uses: brunnojob/devthreat-guard@166415c26c39fab99bf9ecf1413d6a66ef8ea59c
        with:
          path: .
          fail-on: high
          format: sarif
          output: devthreat.sarif
```

Pin DevThreat Guard to an audited full commit SHA in production. Input `output` must point to a new file in an existing directory inside the workspace. The Action does not upload reports or post comments. It exposes `exit-code`. To upload SARIF to GitHub code scanning, add a separately pinned `github/codeql-action/upload-sarif` step with `if: always()` and narrowly scoped `security-events: write`; GitHub availability and plan requirements apply. Do not grant write tokens to untrusted PR code. No paid features are required for the core tool or public Pages demo.

## Reproducible before / after

| Teaching fixture | Before | After manual remediation | What is verified |
|---|---:|---:|---|
| JavaScript | 5 findings | 0 findings | SQL values passed separately, hostile markup rendered as text, invalid IDs rejected |
| Python | 6 findings | 0 findings | SQLite parameter binding, input rejection, structured JSON parsing |

`npm run demo` checks both pairs using the same engine as the browser and CLI. `npm test` and the Python tests validate the fixed boundaries. Vulnerable fixtures are inert source text, never imported or executed. There is no live vulnerable service. See [demo evidence](https://brunnojob.github.io/devthreat-guard/demo-evidence.json).

The tool explains the risky patterns; a developer makes the corrections. It does not automatically rewrite code or guarantee the fixed examples cover authentication, authorization, deployment, dependencies or all possible attacks.

## Exclusions and baselines

Create `.devthreat.json` in the scan root with exact relative paths or directory prefixes (no globs):

```json
{"exclude": ["fixtures", "docs/generated"]}
```

The repository excludes its inert vulnerable fixtures, generated site, tests, teaching content and rule definition file (which contains deliberate matching strings). These exclusions are visible and listed in scan coverage; the rule engine is tested separately. Production code in `src/action.mjs`, `src/defense.mjs`, CLI and corrected examples remains scanned.

```sh
node bin/devthreat-guard.mjs . --format json --output baseline.json --fail-on none
node bin/devthreat-guard.mjs . --baseline baseline.json --format json
```

Baselines accept exact path/rule/line/column fingerprints; moving a line reopens the finding. They do not mean a risk has been fixed. Review baselines and exclusion changes like code. Reports omit source snippets and credential values, but still contain paths and metadata: review before sharing.

## Study and extend

Open the [academy](https://brunnojob.github.io/devthreat-guard/#academy) for injection, XSS, supply chain, identity, recovery and agent trust boundaries. The toolkit explains ZAP, Nmap, Wireshark, sqlmap, Semgrep and Trivy and connects each to preventive controls. The site neither invokes these tools nor scans external targets.

Build locally: `npm run build`, then `python3 -m http.server 8000 --directory site-built`. Open `http://localhost:8000`. Build files have no external runtime scripts, fonts or analytics. Only progress and language are stored in localStorage; source text is not persisted. Hosting providers receive ordinary HTTP metadata. Do not paste secrets into screenshots or share exported reports without review.

See [RESEARCH.md](docs/RESEARCH.md) for the exact source-to-design mapping, dates and uncertainty. Research informs the priorities; it does not validate the scanner. No third-party PDFs are redistributed. Original project code/docs are MIT; external studies retain their own licenses. Tool names belong to their respective owners; no affiliation or endorsement is claimed.

God first. Built by [brunnojob](https://github.com/brunnojob) for developers who want useful security evidence.

An optional [Dependabot configuration example](docs/dependabot-example.yml) is provided for maintainers to enable explicitly; no recurring dependency-update schedule is activated by this repository.
