# CheckWP

CheckWP is an offline-first security scanner for WordPress plugins. It scans plugin directories and `.zip` archives for malware, backdoors, insecure code patterns, and common vulnerability classes such as remote code execution, SQL injection, cross-site scripting, CSRF, unsafe uploads, and privilege issues.

AI verification is optional. The scanner only enables AI support when `--ai-key` is provided.

## What CheckWP does

- Scans plugin directories and plugin ZIP archives
- Validates WordPress plugin structure before scanning
- Detects PHP and JavaScript malware indicators
- Finds common security flaws in plugin code
- Generates HTML, JSON, Markdown, and PDF reports
- Provides a FastAPI service through `checkwp-api`
- Includes `mock-malicious-plugin/` for local validation

## Why the offline mode matters

The default scan is designed to be useful even without any external API. It combines:

1. Signature-based detection
2. Full-file regex matching
3. Context-aware false-positive checks
4. Composite malware heuristics for obfuscation and payload execution

This improves detection of backdoors and suspicious payloads even when AI is not used.

## How it works

| Stage                    | What happens                                                                                       |
|--------------------------|----------------------------------------------------------------------------------------------------|
| Input validation         | CheckWP accepts a plugin folder or ZIP archive and validates that it looks like a WordPress plugin |
| Safe extraction          | ZIP archives are extracted with path traversal and symlink protections                             |
| File discovery           | Files are filtered by extension, size, and excluded folders                                        |
| Offline scan             | Signatures and heuristics are applied across full file content                                     |
| Optional AI verification | If `--ai-key` is present, findings can be reviewed by an OpenAI-compatible endpoint                |
| Reporting                | Results are written as HTML, JSON, Markdown, and PDF                                               |

## Detection coverage

| Category              | Examples                                                                                 |
|-----------------------|------------------------------------------------------------------------------------------|
| Remote code execution | `eval()`, `assert()`, `create_function()`, variable-function execution                   |
| Command injection     | `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()`                            |
| SQL injection         | Unsafe `$wpdb` queries and raw superglobals inside SQL                                   |
| XSS                   | Unescaped output, `innerHTML`, `document.write()`                                        |
| CSRF                  | Form and AJAX handlers without nonce verification                                        |
| File issues           | Dynamic include/require, unsafe file reads, unsafe uploads                               |
| Deserialization       | `unserialize()` on user-controlled input                                                 |
| Authorization         | Public REST routes, weak capability checks                                               |
| Malware indicators    | `eval(base64_decode())`, encoded payloads, exfiltration, hidden admin creation, skimmers |
| Obfuscation           | `chr()` chains, `String.fromCharCode()`, long encoded blobs, entropy spikes              |

## Installation

### pipx

```bash
pipx install checkwp
```

### PyPI / pip

```bash
pip install checkwp
```

### Homebrew

```bash
brew tap thaikolja/checkwp
brew install checkwp
```

### Local development install

```bash
git clone https://gitlab.com/thaikolja/checkwp.git
cd checkwp
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick start

```bash
checkwp ./my-plugin
checkwp ./my-plugin.zip
checkwp ./my-plugin --deep -o report.html --no-open
checkwp ./mock-malicious-plugin --deep --no-open
```

## CLI usage

```text
checkwp <path> [options]
```

### Core options

| Option                                      | Description                                               |
|---------------------------------------------|-----------------------------------------------------------|
| `-o, --output PATH`                         | Output file path                                          |
| `-f, --format {html,json}`                  | Report format                                             |
| `--stdout`                                  | Print report to stdout                                    |
| `--no-open`                                 | Do not auto-open HTML reports                             |
| `-s, --severity {critical,high,medium,low}` | Minimum severity to report                                |
| `--deep`                                    | Enable deeper offline heuristics and entropy-based checks |
| `--quick`                                   | Restrict output to high and critical findings             |
| `-t, --threads N`                           | Number of worker threads                                  |
| `--max-file-size KB`                        | Maximum file size to scan                                 |
| `--context-lines N`                         | Context lines to include around findings                  |
| `--exclude NAME`                            | Exclude a directory name; repeatable                      |
| `--include-ext EXT`                         | Add extra file extensions; repeatable                     |
| `--php-only`                                | Scan PHP-like files only                                  |
| `--js-only`                                 | Scan JavaScript / TypeScript-like files only              |
| `--no-banner`                               | Hide the startup banner                                   |
| `--no-color`                                | Disable colored output                                    |
| `-V, --version`                             | Show version                                              |

### AI options

| Option                   | Description                                                       |
|--------------------------|-------------------------------------------------------------------|
| `--ai-key KEY`           | Enables AI verification                                           |
| `--ai-endpoint URL`      | OpenAI-compatible base URL. If omitted, OpenAI is used by default |
| `--ai-model MODEL`       | Model name for AI verification                                    |
| `--ai-temperature FLOAT` | Sampling temperature                                              |

Important:

- `--ai-endpoint` accepts a full OpenAI-compatible URL only
- No provider aliases are used
- If `--ai-endpoint` is omitted, CheckWP uses `https://api.openai.com/v1`

### AI examples

OpenAI:

```bash
checkwp ./my-plugin \
  --ai-key "sk-..." \
  --ai-model "gpt-4o"
```

DeepSeek with explicit OpenAI-compatible URL:

```bash
checkwp ./my-plugin \
  --ai-key "sk-..." \
  --ai-endpoint "https://api.deepseek.com/v1" \
  --ai-model "deepseek-chat"
```

Generic OpenAI-compatible endpoint:

```bash
checkwp ./my-plugin \
  --ai-key "token" \
  --ai-endpoint "https://example.com/v1" \
  --ai-model "my-model"
```

## API usage

Start the API locally:

```bash
checkwp-api
```

Default local address:

- `http://127.0.0.1:8000`

### API endpoints

| Method | Endpoint                    | Purpose                      |
|--------|-----------------------------|------------------------------|
| `GET`  | `/`                         | Service index                |
| `GET`  | `/health`                   | Health check                 |
| `GET`  | `/version`                  | API version                  |
| `POST` | `/scan`                     | Upload and scan a plugin ZIP |
| `GET`  | `/static/reports/{id}.html` | Access saved HTML reports    |

### Popular OpenAI-compatible endpoint URLs

| Provider   | Base URL for `--ai-endpoint` or `ai_endpoint` |
|------------|-----------------------------------------------|
| OpenAI     | `https://api.openai.com/v1`                   |
| DeepSeek   | `https://api.deepseek.com/v1`                 |
| OpenRouter | `https://openrouter.ai/api/v1`                |
| Groq       | `https://api.groq.com/openai/v1`              |
| Together   | `https://api.together.xyz/v1`                 |

### Upload and scan a ZIP

```bash
curl -X POST "http://127.0.0.1:8000/scan?format=json" \
  -F "file=@./my-plugin.zip"
```

### Upload and scan with AI verification

```bash
curl -X POST "http://127.0.0.1:8000/scan?format=json&ai_key=sk-...&ai_endpoint=https://api.deepseek.com/v1&ai_model=deepseek-chat" \
  -F "file=@./my-plugin.zip"
```

## Reports

| Format   | Use case                                         |
|----------|--------------------------------------------------|
| HTML     | Manual review, sharing, and browser-based triage |
| JSON     | CI/CD, scripting, and automation                 |
| Markdown | Lightweight text reports                         |
| PDF      | Portable report handoff                          |

When HTML output is generated, CheckWP also writes companion `.md` and `.pdf` files.

## Mock plugin for validation

The repository includes `mock-malicious-plugin/`, a deliberately vulnerable sample plugin that contains:

- SQL injection
- XSS
- unsafe redirects
- unsafe uploads
- public REST routes
- hidden admin creation
- obfuscated PHP payloads
- suspicious JavaScript payloads

Run it locally to validate detection quality:

```bash
checkwp ./mock-malicious-plugin --deep --no-open
```

## Development

```bash
pytest
ruff check .
mypy src/
python -m build
```

## Publishing

### PyPI

```bash
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

### pipx

After publishing to PyPI:

```bash
pipx install checkwp
```

### Homebrew

Update `homebrew/checkwp.rb` with the SHA256 of the published PyPI source tarball.

Related files:

- `homebrew/HOMEBREW.md`
- `.github/workflows/release.yml`

## Author

| Field         | Value                                  |
|---------------|----------------------------------------|
| Name          | Kolja Nolte                            |
| Website       | `https://checkwp.org`                  |
| Email         | `kolja.nolte@gmail.com`                |
| GitLab        | `https://gitlab.com/thaikolja/checkwp` |
| GitHub mirror | `https://github.com/thaikolja/checkwp` |

## License

MIT. See `LICENSE`.

