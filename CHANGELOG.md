# CHANGELOG

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-05-09

### Added
- **License**: Added `LICENSE.md` (MIT) to the project root.
- **ZIP File Support**: The scanner now accepts `.zip` files of WordPress plugins. It automatically extracts them to a temporary directory for analysis.
- **Security Linting**: Integrated `bandit` for security linting of the tool's source code.
- **Plugin Validation**: Added verification to ensure ZIP files or directories contain a valid WordPress plugin by checking for the `Plugin Name:` header.
- **AI Usage Guide**: Integrated an interactive AI usage and implementation guide within the HTML report.
- **Enhanced Masthead**: Added advanced scan metrics (health, confidence, distribution) to the report dashboard.
- **Ubuntu Typography**: Rebranded the UI with the Ubuntu font family for better readability.
- **Action Plan**: Added a security hardening checklist at the bottom of the HTML reports.

### Changed
- **Renamed Tool**: Formally renamed the CLI tool to `wpcheck` (previously `checkwp`).
- **UI Refactoring**: Stacked vulnerability details vertically for better mobile and desktop readability.
- **Smooth Transitions**: Added CSS animations and cubic-bezier transitions for expanding finding rows.
- **Environment Standard**: Standardized the environment variable to `WPCHECK_AI_KEY`.

### Fixed
- Fixed an issue where the report wouldn't correctly map relative paths when scanning ZIP files.
- Improved multi-threaded performance by optimizing file discovery logic.
