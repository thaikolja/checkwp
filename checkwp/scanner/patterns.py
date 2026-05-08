"""Vulnerability signature patterns for PHP and JS analysis."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List

class Severity(IntEnum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def color(self) -> str:
        return {5: "#dc2626", 4: "#ea580c", 3: "#d97706", 2: "#2563eb", 1: "#6b7280"}[self.value]

@dataclass(frozen=True)
class VulnPattern:
    id: str
    title: str
    severity: Severity
    pattern: str  # regex
    description: str
    impact: str = ""          # Plain-English impact for non-programmers
    layman_fix: str = ""      # Instructions for non-programmers on how to fix
    step_by_step_fix: list[str] = field(default_factory=list) # Checklist for the user
    cwe: str = ""
    recommendation: str = ""
    confidence: str = "high"
    languages: tuple = ("php",)
    is_regex: bool = True
    context_patterns: tuple = ()  # patterns that, if nearby, confirm the vuln
    false_positive_patterns: tuple = ()  # patterns that, if nearby, negate the vuln

# ─── PHP VULNERABILITY PATTERNS ─────────────────────────────────────
PHP_PATTERNS: List[VulnPattern] = [
    # ── CRITICAL: Remote Code Execution / Backdoors ──
    VulnPattern(
        id="PHP-RCE-001", title="eval() with dynamic input",
        severity=Severity.CRITICAL,
        pattern=r'\beval\s*\(\s*\$',
        description="eval() called with a variable argument enables arbitrary code execution.",
        impact="An attacker could run any code they want on your website's server. This means they could steal your entire database (including customer data and passwords), install malware, deface your site, or use your server to attack others.",
        layman_fix="This code uses a dangerous function called 'eval'. To fix it, you should search for the word 'eval' in this file and see if it can be replaced with a safer way to handle data, like 'json_decode'. If you didn't write this code, contact the plugin developer and ask them to remove 'eval'.",
        step_by_step_fix=[
            "Locate the file mentioned in the report.",
            "Find the line containing `eval()`.",
            "Determine if the data passed to it can be parsed using `json_decode()` instead.",
            "If it's for dynamic code, refactor to use a fixed logic path.",
            "Test the plugin thoroughly to ensure it still works without the dangerous function."
        ],
        cwe="CWE-94", recommendation="Remove eval() entirely. Use safer alternatives like json_decode or specific parsers.",
    ),
    VulnPattern(
        id="PHP-RCE-002", title="eval(base64_decode()) backdoor pattern",
        severity=Severity.CRITICAL,
        pattern=r'\beval\s*\(\s*base64_decode\s*\(',
        description="Classic backdoor pattern: base64-encoded payload executed via eval().",
        impact="This is almost certainly a hidden backdoor. Someone has likely already compromised this plugin. An attacker with access to this backdoor has full control of your server and can steal data, redirect visitors, or inject spam and malware into your site at any time.",
        layman_fix="This is highly suspicious 'obfuscated' code used by hackers. You should delete this file or this entire plugin immediately. Do not try to fix this yourself; your site is likely already hacked and needs a professional security cleanup.",
        cwe="CWE-506", recommendation="Remove immediately. This is almost certainly a backdoor.",
    ),
    VulnPattern(
        id="PHP-RCE-003", title="eval(gzinflate()) obfuscated payload",
        severity=Severity.CRITICAL,
        pattern=r'\beval\s*\(\s*gzinflate\s*\(',
        description="Compressed and obfuscated code executed via eval(). Common malware pattern.",
        impact="Hidden, compressed code is being secretly executed. This is a strong indicator of malware. Your site may already be compromised — attackers could be stealing visitor data, sending spam emails from your server, or silently redirecting your users.",
        cwe="CWE-506", recommendation="Remove immediately and audit the entire plugin.",
    ),
    VulnPattern(
        id="PHP-RCE-004", title="assert() used as code execution",
        severity=Severity.CRITICAL,
        pattern=r'\bassert\s*\(\s*\$',
        description="assert() with variable input can execute arbitrary code (PHP < 8.0 default).",
        impact="An attacker can execute arbitrary commands on your server. This could lead to complete site takeover, data theft, or your server being used for illegal activities without your knowledge.",
        cwe="CWE-94", recommendation="Remove assert() calls with user input. Use proper validation.",
    ),
    VulnPattern(
        id="PHP-RCE-005", title="preg_replace with /e modifier",
        severity=Severity.CRITICAL,
        pattern=r'preg_replace\s*\(\s*["\'][^"\']*\/e["\']',
        description="The /e modifier in preg_replace executes the replacement as PHP code. Removed in PHP 7.",
        impact="Attackers can inject code that gets executed automatically. This could let them take full control of the website, modify content, or steal sensitive information from your database.",
        cwe="CWE-94", recommendation="Use preg_replace_callback() instead.",
    ),
    VulnPattern(
        id="PHP-RCE-006", title="Dynamic function call via variable",
        severity=Severity.HIGH,
        pattern=r'\$\w+\s*\(\s*\$',
        description="Variable function call can execute arbitrary functions if the variable is user-controlled.",
        impact="If exploited, an attacker could trick the plugin into running dangerous operations — potentially deleting files, accessing the database, or taking control of the server.",
        cwe="CWE-94", recommendation="Use a whitelist of allowed function names.",
        confidence="medium",
    ),
    VulnPattern(
        id="PHP-RCE-007", title="create_function() usage",
        severity=Severity.CRITICAL,
        pattern=r'\bcreate_function\s*\(',
        description="create_function() internally uses eval(). Deprecated in PHP 7.2, removed in 8.0.",
        impact="This outdated function can be exploited to run malicious code. An attacker could use it to gain full access to your website, steal data, or install persistent backdoors.",
        cwe="CWE-94", recommendation="Use anonymous functions (closures) instead.",
    ),
    VulnPattern(
        id="PHP-RCE-008", title="call_user_func with variable",
        severity=Severity.HIGH,
        pattern=r'\bcall_user_func(?:_array)?\s*\(\s*\$',
        description="call_user_func with a user-controlled callback enables arbitrary function execution.",
        impact="An attacker could choose which function the server executes, potentially deleting your site content, reading private data, or installing malware.",
        cwe="CWE-94", recommendation="Validate the callback against a whitelist.",
        confidence="medium",
    ),

    # ── CRITICAL: Command Injection ──
    VulnPattern(
        id="PHP-CMD-001", title="system() call",
        severity=Severity.CRITICAL,
        pattern=r'\bsystem\s*\(\s*\$',
        description="system() executes an OS command with user-controlled input.",
        impact="An attacker can run operating system commands directly on your server. They could download malware, read your WordPress configuration (including database passwords), delete all your files, or pivot to attack other sites on the same server.",
        layman_fix="The plugin is trying to talk directly to your server's operating system using 'system()'. This is very risky. Check if there is a plugin update available that fixes this. If not, consider using a different plugin that doesn't require such deep server access.",
        step_by_step_fix=[
            "Search the file for the `system()` function.",
            "Identify why the plugin is running server-level commands.",
            "Replace the command with a built-in WordPress function (e.g., for file management, use `WP_Filesystem`).",
            "If a command is absolutely necessary, ensure the input is cleaned using `escapeshellarg()`."
        ],
        cwe="CWE-78", recommendation="Avoid system calls. If required, use escapeshellarg() and a whitelist.",
    ),
    VulnPattern(
        id="PHP-CMD-002", title="exec() call",
        severity=Severity.CRITICAL,
        pattern=r'\bexec\s*\(\s*\$',
        description="exec() executes an OS command with user-controlled input.",
        impact="An attacker can execute any command on your web server, just as if they were sitting at the keyboard. This means full server compromise — data theft, file deletion, or turning your server into part of a botnet.",
        cwe="CWE-78", recommendation="Avoid exec(). Use WordPress APIs or escapeshellarg().",
    ),
    VulnPattern(
        id="PHP-CMD-003", title="passthru() call",
        severity=Severity.CRITICAL,
        pattern=r'\bpassthru\s*\(\s*\$',
        description="passthru() executes a command and outputs raw results.",
        impact="Attackers can run system commands and see the output directly. This could expose confidential server files, database contents, or allow complete server takeover.",
        cwe="CWE-78", recommendation="Remove passthru() calls entirely.",
    ),
    VulnPattern(
        id="PHP-CMD-004", title="shell_exec() or backticks",
        severity=Severity.CRITICAL,
        pattern=r'\bshell_exec\s*\(\s*\$|`\s*\$[^`]*`',
        description="shell_exec() or backtick operator executes shell commands.",
        impact="An attacker gains the ability to execute any command on the server's operating system. This is equivalent to having direct server access and can lead to complete data breach.",
        cwe="CWE-78", recommendation="Remove shell execution. Use PHP/WordPress native functions.",
    ),
    VulnPattern(
        id="PHP-CMD-005", title="popen() call",
        severity=Severity.CRITICAL,
        pattern=r'\bpopen\s*\(\s*\$',
        description="popen() opens a process with user-controlled command.",
        impact="Attackers can launch long-running processes on your server — like cryptocurrency miners, spam bots, or tools to attack other websites, all using your server resources.",
        cwe="CWE-78", recommendation="Avoid popen(). Use WordPress APIs.",
    ),
    VulnPattern(
        id="PHP-CMD-006", title="proc_open() call",
        severity=Severity.HIGH,
        pattern=r'\bproc_open\s*\(',
        description="proc_open() can execute arbitrary system commands.",
        impact="This function can be used to run background processes on your server, potentially allowing attackers to install persistent malware that survives plugin updates.",
        cwe="CWE-78", recommendation="Avoid proc_open() in plugin code.",
    ),

    # ── HIGH: SQL Injection ──
    VulnPattern(
        id="PHP-SQLI-001", title="Direct variable in SQL query",
        severity=Severity.HIGH,
        pattern=r'\$wpdb\s*->\s*(?:query|get_results|get_row|get_var|get_col)\s*\(\s*["\'].*\$',
        description="SQL query with direct variable interpolation without $wpdb->prepare().",
        impact="An attacker could read, modify, or delete anything in your database — including user accounts, orders, private messages, and admin credentials. They could also extract sensitive data like email addresses and payment information.",
        layman_fix="The code is talking to your database in an 'unprepared' way. To fix this, the developer needs to wrap the query in a '$wpdb->prepare()' function. If you are comfortable editing code, look for '$wpdb->query' and ensure all variables are passed through the prepare method.",
        step_by_step_fix=[
            "Identify the SQL query line in the file.",
            "Locate where variables (like `$id` or `$name`) are being inserted directly into the query string.",
            "Rewrite the query to use placeholders like `%s` (for strings) or `%d` (for numbers).",
            "Pass the actual variables as separate arguments to the `$wpdb->prepare()` function."
        ],
        cwe="CWE-89", recommendation="Always use $wpdb->prepare() for queries with variables.",
        false_positive_patterns=(r'\$wpdb\s*->\s*prepare',),
    ),
    VulnPattern(
        id="PHP-SQLI-002", title="String concatenation in SQL",
        severity=Severity.HIGH,
        pattern=r'\$wpdb\s*->\s*(?:query|get_results|get_row|get_var|get_col)\s*\([^)]*\.\s*\$',
        description="SQL query built via string concatenation with variables.",
        impact="Attackers can inject their own database commands. This could allow them to dump your entire user table, reset admin passwords, or delete critical data.",
        cwe="CWE-89", recommendation="Use $wpdb->prepare() with placeholders (%s, %d).",
    ),
    VulnPattern(
        id="PHP-SQLI-003", title="Raw $_GET/$_POST in SQL",
        severity=Severity.CRITICAL,
        pattern=r'\$wpdb\s*->\s*\w+\s*\([^)]*\$_(?:GET|POST|REQUEST)\b',
        description="Superglobal variables used directly in SQL queries.",
        impact="User-supplied input is passed directly into a database query with zero filtering. Any visitor to your site could exploit this to steal your entire database or gain admin access.",
        cwe="CWE-89", recommendation="Sanitize with $wpdb->prepare(), intval(), or sanitize_text_field().",
    ),
    VulnPattern(
        id="PHP-SQLI-004", title="Unsafe LIKE query",
        severity=Severity.MEDIUM,
        pattern=r'LIKE\s*["\'][^"\']*\$',
        description="LIKE clause with variable interpolation. May allow SQL wildcard injection.",
        impact="An attacker could manipulate search queries to extract data they shouldn't have access to, or cause your database to run very slow queries that crash your site.",
        cwe="CWE-89", recommendation="Use $wpdb->esc_like() before $wpdb->prepare().",
    ),

    # ── HIGH: Cross-Site Scripting (XSS) ──
    VulnPattern(
        id="PHP-XSS-001", title="Unescaped echo of superglobal",
        severity=Severity.HIGH,
        pattern=r'\becho\s+\$_(?:GET|POST|REQUEST|SERVER|COOKIE)\b',
        description="Direct output of superglobal variables without escaping.",
        impact="Attackers can inject malicious scripts that run in your visitors' browsers. This could steal login cookies, redirect users to phishing pages, or display fake login forms that capture passwords.",
        layman_fix="The plugin is 'echoing' (printing) data from a user's request without cleaning it first. You can fix this by wrapping the variable in 'esc_html()'. For example, change 'echo $_GET[\"name\"]' to 'echo esc_html($_GET[\"name\"])'.",
        step_by_step_fix=[
            "Find the `echo` statement mentioned in the report.",
            "Identify the variable being displayed (e.g., `$_GET[...]` or `$user_input`).",
            "Wrap that variable in `esc_html()` if it's text, or `esc_attr()` if it's inside an HTML attribute.",
            "Refresh your site and verify the output still looks correct."
        ],
        cwe="CWE-79", recommendation="Use esc_html(), esc_attr(), or esc_url() before output.",
    ),
    VulnPattern(
        id="PHP-XSS-002", title="Unescaped echo of variable",
        severity=Severity.MEDIUM,
        pattern=r'\becho\s+["\']?[^;]*\$(?!wpdb)\w+',
        description="Variable echoed without WordPress escaping functions.",
        impact="Could allow attackers to inject scripts into your pages. Visitors may have their sessions hijacked, see fake content, or be redirected to malicious websites.",
        cwe="CWE-79", recommendation="Wrap in esc_html(), esc_attr(), or wp_kses().",
        confidence="medium",
        false_positive_patterns=(r'esc_html|esc_attr|esc_url|wp_kses|esc_textarea',),
    ),
    VulnPattern(
        id="PHP-XSS-003", title="Reflected input via $_SERVER['REQUEST_URI']",
        severity=Severity.HIGH,
        pattern=r"""\$_SERVER\s*\[\s*['"]REQUEST_URI['"]\s*\]""",
        description="REQUEST_URI can contain user-controlled values; output without escaping causes XSS.",
        impact="A specially crafted URL could inject scripts into your admin pages. If an admin clicks the link, an attacker could take over their account.",
        cwe="CWE-79", recommendation="Use esc_url() or esc_attr() when outputting.",
        confidence="medium",
    ),
    VulnPattern(
        id="PHP-XSS-004", title="Reflected input via $_SERVER['PHP_SELF']",
        severity=Severity.HIGH,
        pattern=r"""\$_SERVER\s*\[\s*['"]PHP_SELF['"]\s*\]""",
        description="PHP_SELF is user-controllable and can lead to reflected XSS.",
        impact="Attackers can craft malicious links that, when clicked by your users, execute harmful scripts in their browser — potentially stealing their login sessions.",
        cwe="CWE-79", recommendation="Use esc_url() or admin_url() instead.",
    ),

    # ── HIGH: CSRF ──
    VulnPattern(
        id="PHP-CSRF-001", title="Form handler without nonce verification",
        severity=Severity.HIGH,
        pattern=r'if\s*\(\s*isset\s*\(\s*\$_(?:POST|GET|REQUEST)\b[^)]*\)\s*\)',
        description="Form/request handler that checks for submitted data without nonce verification.",
        impact="An attacker could trick a logged-in admin into unknowingly submitting a hidden form — changing plugin settings, creating accounts, or modifying site content without the admin's knowledge.",
        cwe="CWE-352", recommendation="Add wp_verify_nonce() or check_admin_referer() before processing.",
        confidence="medium",
        false_positive_patterns=(r'wp_verify_nonce|check_admin_referer|check_ajax_referer',),
    ),
    VulnPattern(
        id="PHP-CSRF-002", title="AJAX handler without nonce check",
        severity=Severity.HIGH,
        pattern=r'wp_ajax_(?:nopriv_)?\w+.*(?:function\s+\w+|[\'"]\s*,\s*function)',
        description="AJAX handler registered without visible nonce verification.",
        impact="Malicious websites could silently trigger actions on your WordPress site while your admin is browsing, potentially changing settings or exfiltrating data.",
        cwe="CWE-352", recommendation="Use check_ajax_referer() at the start of the handler.",
        confidence="medium",
    ),

    # ── HIGH: File Inclusion ──
    VulnPattern(
        id="PHP-LFI-001", title="Dynamic include/require with variable",
        severity=Severity.HIGH,
        pattern=r'\b(?:include|require)(?:_once)?\s*\(\s*\$',
        description="File inclusion with a variable path can lead to Local File Inclusion (LFI).",
        impact="An attacker could read any file on your server — including wp-config.php (which contains your database password), private keys, and other sensitive configuration. They might also execute malicious code.",
        cwe="CWE-98", recommendation="Use a whitelist of allowed files. Never include user-controlled paths.",
    ),
    VulnPattern(
        id="PHP-LFI-002", title="File read with user input",
        severity=Severity.HIGH,
        pattern=r'\bfile_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)',
        description="Reading files based on user input can expose sensitive files.",
        impact="An attacker could read sensitive files like password files, configuration files with database credentials, or private user data stored on the server.",
        cwe="CWE-22", recommendation="Validate and sanitize file paths. Use a whitelist.",
    ),

    # ── HIGH: File Upload ──
    VulnPattern(
        id="PHP-UPLOAD-001", title="Direct move_uploaded_file without validation",
        severity=Severity.HIGH,
        pattern=r'\bmove_uploaded_file\s*\(',
        description="File upload handler detected. Ensure MIME type, extension, and size validation.",
        impact="Without proper validation, an attacker could upload a malicious PHP file disguised as an image, then execute it to gain full control of your website.",
        cwe="CWE-434", recommendation="Use wp_handle_upload() with strict type checking.",
        confidence="medium",
    ),

    # ── HIGH: Deserialization ──
    VulnPattern(
        id="PHP-DESER-001", title="unserialize() with user input",
        severity=Severity.CRITICAL,
        pattern=r'\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
        description="Deserializing user input can lead to Object Injection attacks.",
        impact="An attacker can craft special data that, when processed, executes arbitrary code on your server. This can lead to complete site takeover, file deletion, or data theft.",
        cwe="CWE-502", recommendation="Use json_decode() instead. Never unserialize user input.",
    ),
    VulnPattern(
        id="PHP-DESER-002", title="unserialize() usage",
        severity=Severity.MEDIUM,
        pattern=r'\bunserialize\s*\(\s*\$',
        description="unserialize() with variable input. Verify the source is trusted.",
        impact="If the data source is compromised, attackers could exploit this to execute code on your server or manipulate your site's behavior.",
        cwe="CWE-502", recommendation="Prefer json_decode(). If unserialize is needed, use allowed_classes option.",
        confidence="medium",
    ),

    # ── MEDIUM: Authentication / Authorization ──
    VulnPattern(
        id="PHP-AUTH-001", title="Missing capability check",
        severity=Severity.MEDIUM,
        pattern=r'(?:add_action|add_filter)\s*\(\s*[\'"](?:wp_ajax_|admin_)',
        description="Admin/AJAX action registered. Ensure current_user_can() is checked.",
        impact="Without proper permission checks, any logged-in user — even subscribers — could access admin-only functionality, potentially modifying settings, viewing private data, or escalating their privileges.",
        cwe="CWE-862", recommendation="Add current_user_can() check at the start of the callback.",
        confidence="medium",
        false_positive_patterns=(r'current_user_can',),
    ),
    VulnPattern(
        id="PHP-AUTH-002", title="is_admin() used for authorization",
        severity=Severity.MEDIUM,
        pattern=r'\bis_admin\s*\(\s*\)',
        description="is_admin() checks if on an admin page, NOT if the user is an admin.",
        impact="Developers often misuse this as a security check. Regular users who somehow access admin pages would bypass this check, potentially accessing sensitive functionality.",
        cwe="CWE-862", recommendation="Use current_user_can('manage_options') for authorization.",
        confidence="low",
    ),

    # ── MEDIUM: Open Redirect ──
    VulnPattern(
        id="PHP-REDIR-001", title="Unsafe redirect with user input",
        severity=Severity.MEDIUM,
        pattern=r'\bwp_redirect\s*\(\s*\$_(?:GET|POST|REQUEST)',
        description="Redirect destination from user input can be exploited for phishing.",
        impact="An attacker could craft a link that appears to be on your site but redirects visitors to a fake login page that steals their credentials.",
        cwe="CWE-601", recommendation="Use wp_safe_redirect() and wp_validate_redirect().",
    ),
    VulnPattern(
        id="PHP-REDIR-002", title="header() redirect with variable",
        severity=Severity.MEDIUM,
        pattern=r'\bheader\s*\(\s*["\']Location:\s*["\']?\s*\.\s*\$',
        description="PHP header redirect with unsanitized variable.",
        impact="Users could be silently redirected to phishing sites or malware downloads through crafted URLs shared via email or social media.",
        cwe="CWE-601", recommendation="Use wp_safe_redirect() instead of header().",
    ),

    # ── MEDIUM: Information Disclosure ──
    VulnPattern(
        id="PHP-INFO-001", title="phpinfo() call",
        severity=Severity.MEDIUM,
        pattern=r'\bphpinfo\s*\(',
        description="phpinfo() exposes sensitive server configuration details.",
        impact="Reveals your server's PHP version, installed modules, file paths, and environment variables to anyone who can access it — providing attackers with a detailed roadmap for targeting your specific setup.",
        cwe="CWE-200", recommendation="Remove phpinfo() calls from production code.",
    ),
    VulnPattern(
        id="PHP-INFO-002", title="Error display enabled",
        severity=Severity.LOW,
        pattern=r'(?:ini_set|error_reporting)\s*\([^)]*(?:E_ALL|display_errors)',
        description="Debug error display should not be in production code.",
        impact="Detailed error messages can reveal database table names, file paths, and code structure to attackers, making it easier for them to find and exploit other vulnerabilities.",
        cwe="CWE-209", recommendation="Remove debug error settings. Use WP_DEBUG only in development.",
    ),
    VulnPattern(
        id="PHP-INFO-003", title="var_dump/print_r in production",
        severity=Severity.LOW,
        pattern=r'\b(?:var_dump|print_r|var_export)\s*\(\s*\$',
        description="Debug output functions should not appear in production code.",
        impact="Debug output may accidentally expose sensitive data like user information, API keys, or internal system details to website visitors.",
        cwe="CWE-200", recommendation="Remove debug output before release.",
    ),

    # ── MEDIUM: Cryptographic Issues ──
    VulnPattern(
        id="PHP-CRYPTO-001", title="MD5 used for security purposes",
        severity=Severity.MEDIUM,
        pattern=r'\bmd5\s*\(\s*\$(?!file)',
        description="MD5 is cryptographically broken for security use (passwords, tokens).",
        impact="Passwords hashed with MD5 can be cracked in seconds using modern hardware. If your database is breached, all user passwords would be immediately exposed.",
        cwe="CWE-328", recommendation="Use wp_hash_password() or password_hash() for passwords.",
        confidence="medium",
    ),
    VulnPattern(
        id="PHP-CRYPTO-002", title="SHA1 used for security purposes",
        severity=Severity.MEDIUM,
        pattern=r'\bsha1\s*\(\s*\$',
        description="SHA1 is considered weak for security-critical operations.",
        impact="SHA1 has known collision attacks. Security tokens or password hashes using SHA1 can potentially be forged or cracked faster than with modern algorithms.",
        cwe="CWE-328", recommendation="Use hash('sha256', ...) or WordPress native hashing.",
        confidence="medium",
    ),
    VulnPattern(
        id="PHP-CRYPTO-003", title="Hardcoded cryptographic key",
        severity=Severity.HIGH,
        pattern=r"""(?:secret|key|password|token|api_key|apikey)\s*(?:=|=>)\s*['"][A-Za-z0-9+/=]{8,}['"]""",
        description="Hardcoded secrets in source code can be extracted by attackers.",
        impact="Anyone who can view the plugin code (including from the WordPress plugin repository) can see these credentials. This could give attackers access to third-party services, payment processors, or your site's API endpoints.",
        cwe="CWE-798", recommendation="Use wp_options, environment variables, or wp-config.php constants.",
        confidence="medium",
    ),

    # ── CRITICAL: Backdoor / Malware Indicators ──
    VulnPattern(
        id="PHP-MALWARE-001", title="Base64 decode + eval chain",
        severity=Severity.CRITICAL,
        pattern=r'(?:eval|assert|system|exec)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)\s*\(',
        description="Multi-layer obfuscation chain — strong indicator of a backdoor.",
        impact="This is a classic malware signature. The code is deliberately hidden to avoid detection. Your site is very likely compromised and may be actively being used to attack visitors, send spam, or steal data.",
        cwe="CWE-506",
        recommendation="Remove immediately. Audit the full plugin for compromise.",
    ),
    VulnPattern(
        id="PHP-MALWARE-002", title="Suspicious long base64 string",
        severity=Severity.HIGH,
        pattern=r"""['"][A-Za-z0-9+/]{100,}={0,2}['"]""",
        description="Very long base64-encoded string, often used to hide malicious payloads.",
        impact="Large encoded strings are commonly used to hide malware. The hidden content could be a webshell, spam injector, or data-stealing script that activates without your knowledge.",
        cwe="CWE-506", recommendation="Decode and inspect the content. Remove if malicious.",
        confidence="medium",
    ),
    VulnPattern(
        id="PHP-MALWARE-003", title="Hex-encoded string execution",
        severity=Severity.CRITICAL,
        pattern=r'(?:eval|assert)\s*\(\s*(?:pack\s*\(\s*["\']H\*["\']|hex2bin)',
        description="Hex-encoded payload executed dynamically — malware indicator.",
        impact="Code is being hidden using hexadecimal encoding to avoid detection. This is a telltale sign of malware that could be doing anything from stealing data to creating backdoor accounts.",
        cwe="CWE-506", recommendation="Remove immediately.",
    ),
    VulnPattern(
        id="PHP-MALWARE-004", title="Remote file access via URL",
        severity=Severity.HIGH,
        pattern=r'(?:file_get_contents|fopen|include|require)\s*\(\s*["\']https?://',
        description="Loading remote content/code can introduce malware or exfiltrate data.",
        impact="The plugin is downloading content from external servers. This could be used to load malware updates, send your site's data to third parties, or inject advertising/spam content that changes over time.",
        cwe="CWE-829", recommendation="Use WordPress HTTP API (wp_remote_get) with URL validation.",
        confidence="medium",
    ),
    VulnPattern(
        id="PHP-MALWARE-005", title="Webshell pattern: $_GET/$_POST in eval/exec",
        severity=Severity.CRITICAL,
        pattern=r'(?:eval|assert|system|exec|passthru|shell_exec)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
        description="Classic webshell: direct execution of user-supplied input.",
        impact="This is a live webshell — it allows anyone who knows the URL to execute any command on your server. Your site is compromised. Attackers have full control and may have already stolen data or installed additional backdoors.",
        cwe="CWE-94", recommendation="Remove immediately. The plugin is compromised.",
    ),
    VulnPattern(
        id="PHP-MALWARE-006", title="Hidden admin user creation",
        severity=Severity.CRITICAL,
        pattern=r'wp_(?:create_user|insert_user)\s*\(',
        description="User creation in plugin code. Verify this is intentional and authorized.",
        impact="Malware commonly creates hidden administrator accounts so attackers can log into your WordPress dashboard at any time — even after you remove the malicious plugin.",
        cwe="CWE-506", recommendation="Audit the context. Malware often creates hidden admin accounts.",
        confidence="medium",
    ),
    VulnPattern(
        id="PHP-MALWARE-007", title="Suspicious chr() string building",
        severity=Severity.HIGH,
        pattern=r'(?:chr\s*\(\s*\d+\s*\)\s*\.?\s*){5,}',
        description="Building strings via chr() calls — common obfuscation to hide malicious code.",
        impact="The code is deliberately obscured character by character. This is a common technique to hide malicious function names and URLs from security scanners and human reviewers.",
        cwe="CWE-506", recommendation="Decode and inspect the constructed string.",
    ),
    VulnPattern(
        id="PHP-MALWARE-008", title="str_rot13 obfuscation",
        severity=Severity.MEDIUM,
        pattern=r'\bstr_rot13\s*\(\s*["\']',
        description="ROT13 used to obfuscate strings — sometimes used to hide malicious intent.",
        impact="While ROT13 is a simple encoding, its use in a WordPress plugin is unusual and may indicate an attempt to hide malicious URLs, function calls, or other suspicious content from reviewers.",
        cwe="CWE-506", recommendation="Decode and inspect. Remove if concealing harmful code.",
        confidence="medium",
    ),
    VulnPattern(
        id="PHP-MALWARE-009", title="Data exfiltration via cURL",
        severity=Severity.HIGH,
        pattern=r'curl_setopt\s*\([^)]*CURLOPT_POSTFIELDS\s*,[^)]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)',
        description="Sending superglobal data to external servers — possible data exfiltration.",
        impact="Your visitors' personal data (IP addresses, form submissions, cookies) may be secretly sent to external servers controlled by attackers. This is a serious privacy violation and potential GDPR/legal issue.",
        cwe="CWE-200", recommendation="Remove and audit what data is being transmitted.",
    ),
    VulnPattern(
        id="PHP-MALWARE-010", title="Cryptocurrency miner pattern",
        severity=Severity.CRITICAL,
        pattern=r'(?:coinhive|cryptonight|minero|coin-hive|CoinImp)',
        description="Cryptocurrency miner code detected — unauthorized resource usage.",
        impact="Your visitors' computers and phones are being secretly used to mine cryptocurrency for the attacker. This slows down their devices, drains batteries, increases electricity costs, and can damage your site's reputation and SEO ranking.",
        cwe="CWE-506", recommendation="Remove immediately.",
        confidence="high",
    ),

    # ── LOW: Best Practice Violations ──
    VulnPattern(
        id="PHP-BP-001", title="Direct use of $_GET/$_POST without sanitization",
        severity=Severity.LOW,
        pattern=r'\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"][^\]]+[\'"]\s*\](?!\s*\))',
        description="Superglobal used without immediate sanitization.",
        impact="User input is being used without cleaning it first. While not always exploitable on its own, this is poor practice that makes other vulnerabilities (like XSS or SQL injection) more likely.",
        cwe="CWE-20", recommendation="Wrap in sanitize_text_field(), intval(), or absint().",
        confidence="low",
    ),
    VulnPattern(
        id="PHP-BP-002", title="extract() usage",
        severity=Severity.MEDIUM,
        pattern=r'\bextract\s*\(\s*\$',
        description="extract() imports variables into scope, risking variable overwrite attacks.",
        impact="An attacker could potentially overwrite important internal variables, bypassing security checks or changing the plugin's behavior in unexpected ways.",
        cwe="CWE-621", recommendation="Access array values directly instead of using extract().",
    ),
    VulnPattern(
        id="PHP-BP-003", title="Deprecated MySQL functions",
        severity=Severity.LOW,
        pattern=r'\bmysql_(?:query|connect|select_db|fetch)\s*\(',
        description="Deprecated mysql_* functions. WordPress uses $wpdb internally.",
        impact="These outdated database functions lack modern security features. Using them indicates the code hasn't been maintained and may be vulnerable to SQL injection attacks.",
        cwe="CWE-477", recommendation="Use $wpdb methods instead of raw MySQL functions.",
    ),
]

# ─── JAVASCRIPT VULNERABILITY PATTERNS ──────────────────────────────
JS_PATTERNS: List[VulnPattern] = [
    VulnPattern(
        id="JS-XSS-001", title="innerHTML assignment with variable",
        severity=Severity.MEDIUM,
        pattern=r'\.innerHTML\s*=\s*(?![\s]*["\']<)',
        description="Setting innerHTML with dynamic content can introduce DOM-based XSS.",
        impact="An attacker could inject malicious scripts into your page that steal visitor data, hijack sessions, or redirect users to dangerous websites.",
        cwe="CWE-79", recommendation="Use textContent or DOMPurify.sanitize().",
        languages=("js", "jsx", "ts", "tsx"),
    ),
    VulnPattern(
        id="JS-XSS-002", title="document.write() usage",
        severity=Severity.MEDIUM,
        pattern=r'\bdocument\.write\s*\(',
        description="document.write() can introduce XSS and degrades performance.",
        impact="Attackers could inject content directly into your page. Visitors might see fake forms, malicious downloads, or be redirected without warning.",
        cwe="CWE-79", recommendation="Use DOM manipulation methods instead.",
        languages=("js", "jsx", "ts", "tsx"),
    ),
    VulnPattern(
        id="JS-RCE-001", title="eval() in JavaScript",
        severity=Severity.HIGH,
        pattern=r'\beval\s*\(',
        description="eval() executes arbitrary JavaScript — major security risk.",
        impact="If an attacker can control what gets evaluated, they can run any JavaScript in your users' browsers — stealing cookies, form data, or redirecting to malicious sites.",
        cwe="CWE-94", recommendation="Use JSON.parse() or Function() with extreme caution.",
        languages=("js", "jsx", "ts", "tsx"),
    ),
    VulnPattern(
        id="JS-RCE-002", title="Function() constructor",
        severity=Severity.HIGH,
        pattern=r'\bnew\s+Function\s*\(',
        description="Function constructor is equivalent to eval() and poses the same risks.",
        impact="Similar to eval(), this can be exploited to run arbitrary JavaScript, potentially stealing user data or hijacking browsing sessions.",
        cwe="CWE-94", recommendation="Refactor to avoid dynamic code generation.",
        languages=("js", "jsx", "ts", "tsx"),
    ),
    VulnPattern(
        id="JS-AJAX-001", title="AJAX call without nonce",
        severity=Severity.MEDIUM,
        pattern=r'(?:jQuery\.(?:ajax|post|get)|fetch|XMLHttpRequest).*admin-ajax\.php',
        description="AJAX call to WordPress without nonce parameter.",
        impact="Without a security token, other websites could trick your visitors' browsers into making requests to your WordPress site, potentially changing settings or triggering actions without consent.",
        cwe="CWE-352", recommendation="Include wp_nonce in AJAX requests using wp_create_nonce().",
        languages=("js", "jsx", "ts", "tsx"),
        confidence="medium",
    ),
    VulnPattern(
        id="JS-PROTO-001", title="Prototype pollution risk",
        severity=Severity.MEDIUM,
        pattern=r'(?:__proto__|constructor\s*\[\s*["\']prototype["\']\s*\])',
        description="Potential prototype pollution vector.",
        impact="An attacker could modify how JavaScript objects behave globally, potentially bypassing security checks, causing the application to crash, or injecting malicious behavior.",
        cwe="CWE-1321", recommendation="Validate object keys. Use Object.create(null) for dictionaries.",
        languages=("js", "jsx", "ts", "tsx"),
    ),
    VulnPattern(
        id="JS-EXT-001", title="External script loading",
        severity=Severity.MEDIUM,
        pattern=r'(?:createElement\s*\(\s*["\']script["\']|\.src\s*=\s*["\']https?://)',
        description="Dynamic loading of external scripts can introduce supply-chain risks.",
        impact="If the external server is compromised, malicious JavaScript could be loaded onto your site without any changes to your own code — affecting all your visitors silently.",
        cwe="CWE-829", recommendation="Load scripts via wp_enqueue_script() with integrity checks.",
        languages=("js", "jsx", "ts", "tsx"),
        confidence="medium",
    ),
]

ALL_PATTERNS = PHP_PATTERNS + JS_PATTERNS

LANGUAGE_EXTENSIONS = {
    "php": (".php", ".inc", ".module"),
    "js": (".js", ".jsx", ".mjs"),
    "ts": (".ts", ".tsx"),
}
