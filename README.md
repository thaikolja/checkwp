# checkwp

A production-ready CLI tool for detecting malware, backdoors, adware, and security vulnerabilities in WordPress plugins. Works fully offline with 50+ built-in detection rules, with optional AI-enhanced analysis via any OpenAI-compatible API.

## Features

- **50+ vulnerability signatures** — SQL injection, XSS, CSRF, RCE, command injection, file inclusion, deserialization, backdoors, cryptominers, and more
- **ZIP & Directory Support** — Scan extracted plugin folders or directly upload `.zip` archives.
- **Plugin Validation** — Automatically verifies WordPress plugin headers before scanning.
- **Multi-threaded scanning** for fast analysis
- **Professional HTML reports** — High-fidelity reports with Ubuntu typography, interactive transitions, and actionable remediation guides.
- **JSON output** for CI/CD integration
- **Deep scan mode** — Entropy analysis for obfuscated code detection
- **Optional AI analysis** — uses any OpenAI-compatible API to verify findings and reduce false positives
- **Zero LLM dependency** — works completely offline by default

## Installation

There are multiple ways to install checkwp.

### 1. via pipx (Recommended)
`pipx` is the recommended way to install Python CLI applications in isolated environments.
```bash
pipx install checkwp
```

### 2. via PyPI (pip)
You can install it directly into your global Python environment or a virtual environment:
```bash
pip install checkwp
```

### 3. via Homebrew (macOS / Linux)
If you prefer Homebrew, you can install it using our custom tap:
```bash
brew tap koljanolte/checkwp
brew install checkwp
```

### 4. via Git (Development)
If you want to modify the source code or run the latest unreleased version:
```bash
git clone https://gitlab.com/koljanolte/checkwp.git
cd checkwp
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

*Note: This project is primarily hosted on [GitLab](https://gitlab.com/koljanolte/checkwp) and mirrored to [GitHub](https://github.com/koljanolte/checkwp). Visit [checkwp.org](https://checkwp.org) for more information.*

## Quick Start

```bash
# Scan a directory
checkwp ./my-plugin

# Scan a ZIP file
checkwp ./my-plugin.zip

# Deep scan with HTML report
checkwp ./my-plugin --deep -o report.html
```

## CLI Reference

```
checkwp <path> [options]

Positional:
  path                    Plugin directory or .zip file to scan

Output:
  -o, --output PATH       Output file path
  -f, --format {html,json} Report format (default: html)
  --no-open               Don't auto-open report in browser
  --stdout                Print report to stdout

Scan:
  -s, --severity LEVEL    Minimum: critical, high, medium, low
  --deep                  Entropy analysis + broader matching
  --quick                 Critical + high severity only
  -t, --threads N         Parallel threads (default: 4)
  --max-file-size KB      Max file size in KB (default: 2048)
  --context-lines N       Context lines around findings (default: 3)

Filter:
  --exclude DIR           Exclude directories (repeatable)
  --include-ext EXT       Additional extensions (repeatable)
  --php-only              PHP files only
  --js-only               JS/TS files only

AI (Optional):
  --ai                    Enable AI-enhanced analysis
  --ai-key KEY            API key (or CHECKWP_AI_KEY env var)
  --ai-provider URL       OpenAI-compatible base URL
  --ai-model MODEL        Model name (default: gpt-4o)
  --ai-temperature FLOAT  Model temperature (default: 0.1)

Display:
  -v, --verbose           Increase verbosity (-v, -vv, -vvv)
  -q, --quiet             Suppress console output
  --no-banner             Hide ASCII banner
  --no-color              Disable colors
  -V, --version           Show version
```

## What It Detects

| Category | Examples |
|----------|---------|
| **Remote Code Execution** | `eval()`, `create_function()`, `assert()`, `preg_replace /e` |
| **Command Injection** | `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()` |
| **SQL Injection** | Direct `$wpdb` queries without `prepare()`, superglobals in SQL |
| **Cross-Site Scripting** | Unescaped output, `$_SERVER['REQUEST_URI']`, DOM XSS |
| **CSRF** | Missing nonce verification in form/AJAX handlers |
| **File Inclusion** | Dynamic `include`/`require` with variables |
| **Backdoors/Malware** | `eval(base64_decode())`, webshells, cryptominers, data exfiltration |
| **Authentication** | Missing `current_user_can()`, `is_admin()` misuse |
| **Cryptographic** | MD5/SHA1 for passwords, hardcoded secrets |
| **Information Disclosure** | `phpinfo()`, debug output, error display |

## License

MIT
