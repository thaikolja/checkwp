"""
Vulnerability signature patterns for PHP and JS analysis.
This module defines the database of regex signatures, impact analysis, and remediation guides.
"""

# Enable future type annotations
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


# Define severity levels as an integer-backed enumeration
class Severity(IntEnum):
    # Highest priority
    CRITICAL = 5
    # High priority
    HIGH = 4
    # Medium priority
    MEDIUM = 3
    # Low priority
    LOW = 2

    @property
    def label(self) -> str:
        """Return the human-readable capitalized name of the severity."""
        # Convert enum name to title case
        return self.name.capitalize()

    @property
    def color(self) -> str:
        """Return the HEX color string associated with this severity level."""
        # Mapping of severity values to HEX codes
        return {5: "#dc2626", 4: "#ea580c", 3: "#d97706", 2: "#2563eb"}[self.value]

@dataclass(frozen=True)
class VulnPattern:
    """
    Data model for a vulnerability signature.
    Includes technical detection logic and non-technical explanation content.
    """
    # Unique identifier for the rule
    id: str
    # Short descriptive title
    title: str
    # Severity level
    severity: Severity
    # Regular expression string used for matching
    pattern: str
    # Detailed technical explanation
    description: str
    # Plain-English impact description for non-technical users
    impact: str = ""
    # Simple fix instructions for site owners
    layman_fix: str = ""
    # Step-by-step checklist for developers
    step_by_step_fix: list[str] = field(default_factory=list)
    # Common Weakness Enumeration ID
    cwe: str = ""
    # Recommended coding alternative
    recommendation: str = ""
    # How confident we are in this signature (high/medium/low)
    confidence: str = "high"
    # Supported programming languages
    languages: tuple = ("php",)
    # Whether the pattern is a regex or literal
    is_regex: bool = True
    # Contextual patterns that verify a finding
    context_patterns: tuple = ()
    # Contextual patterns that indicate a false positive
    false_positive_patterns: tuple = ()

# ─── PHP VULNERABILITY PATTERNS ─────────────────────────────────────
# Collection of security signatures targeting PHP code
PHP_PATTERNS: list[VulnPattern] = [
    # ── CRITICAL: Remote Code Execution / Backdoors ──
    # High-impact rules for code execution vulnerabilities
    VulnPattern(
        # ID for eval with dynamic input
        id="PHP-RCE-001", title="eval() with dynamic input",
        # Set to critical
        severity=Severity.CRITICAL,
        # Regex to find eval with variable
        pattern=r'\beval\s*\(\s*\$',
        # Description
        description="eval() called with a variable argument enables arbitrary code execution.",
        # Impact text
        impact="An attacker could run any code they want on your website's server. This means they could steal your entire database (including customer data and passwords), install malware, deface your site, or use your server to attack others.",
        # Layman fix text
        layman_fix="This code uses a dangerous function called 'eval'. To fix it, you should search for the word 'eval' in this file and see if it can be replaced with a safer way to handle data, like 'json_decode'. If you didn't write this code, contact the plugin developer and ask them to remove 'eval'.",
        # Developer checklist
        step_by_step_fix=[
            "Locate the file mentioned in the report.",
            "Find the line containing `eval()`.",
            "Determine if the data passed to it can be parsed using `json_decode()` instead.",
            "If it's for dynamic code, refactor to use a fixed logic path.",
            "Test the plugin thoroughly to ensure it still works without the dangerous function."
        ],
        # CWE and Recommendation
        cwe="CWE-94", recommendation="Remove eval() entirely. Use safer alternatives like json_decode or specific parsers.",
    ),
    # Backdoor pattern check
    VulnPattern(
        # ID for base64 eval
        id="PHP-RCE-002", title="eval(base64_decode()) backdoor pattern",
        # Set to critical
        severity=Severity.CRITICAL,
        # Regex for common malware signature
        pattern=r'\beval\s*\(\s*base64_decode\s*\(',
        # Description
        description="Classic backdoor pattern: base64-encoded payload executed via eval().",
        # Impact
        impact="This is almost certainly a hidden backdoor. Someone has likely already compromised this plugin. An attacker with access to this backdoor has full control of your server and can steal data, redirect visitors, or inject spam and malware into your site at any time.",
        # Layman fix
        layman_fix="This is highly suspicious 'obfuscated' code used by hackers. You should delete this file or this entire plugin immediately. Do not try to fix this yourself; your site is likely already hacked and needs a professional security cleanup.",
        # CWE and Recommendation
        cwe="CWE-506", recommendation="Remove immediately. This is almost certainly a backdoor.",
    ),
    # Obfuscated payload check
    VulnPattern(
        # ID
        id="PHP-RCE-003", title="eval(gzinflate()) obfuscated payload",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'\beval\s*\(\s*gzinflate\s*\(',
        # Description
        description="Compressed and obfuscated code executed via eval(). Common malware pattern.",
        # Impact
        impact="Hidden, compressed code is being secretly executed. This is a strong indicator of malware. Your site may already be compromised — attackers could be stealing visitor data, sending spam emails from your server, or silently redirecting your users.",
        # Metadata
        cwe="CWE-506", recommendation="Remove immediately and audit the entire plugin.",
    ),
    # Assert usage check
    VulnPattern(
        # ID
        id="PHP-RCE-004", title="assert() used as code execution",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'\bassert\s*\(\s*\$',
        # Description
        description="assert() with variable input can execute arbitrary code (PHP < 8.0 default).",
        # Impact
        impact="An attacker can execute arbitrary commands on your server. This could lead to complete site takeover, data theft, or your server being used for illegal activities without your knowledge.",
        # Metadata
        cwe="CWE-94", recommendation="Remove assert() calls with user input. Use proper validation.",
    ),
    # Unsafe regex check
    VulnPattern(
        # ID
        id="PHP-RCE-005", title="preg_replace with /e modifier",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'preg_replace\s*\(\s*["\'][^"\']*\/e["\']',
        # Description
        description="The /e modifier in preg_replace executes the replacement as PHP code. Removed in PHP 7.",
        # Impact
        impact="Attackers can inject code that gets executed automatically. This could let them take full control of the website, modify content, or steal sensitive information from your database.",
        # Metadata
        cwe="CWE-94", recommendation="Use preg_replace_callback() instead.",
    ),
    # Dynamic function call check
    VulnPattern(
        # ID
        id="PHP-RCE-006", title="Dynamic function call via variable",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'\$\w+\s*\(\s*\$',
        # Description
        description="Variable function call can execute arbitrary functions if the variable is user-controlled.",
        # Impact
        impact="If exploited, an attacker could trick the plugin into running dangerous operations — potentially deleting files, accessing the database, or taking control of the server.",
        # Metadata
        cwe="CWE-94", recommendation="Use a whitelist of allowed function names.",
        # Lower confidence
        confidence="medium",
    ),
    # Deprecated function check
    VulnPattern(
        # ID
        id="PHP-RCE-007", title="create_function() usage",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'\bcreate_function\s*\(',
        # Description
        description="create_function() internally uses eval(). Deprecated in PHP 7.2, removed in 8.0.",
        # Impact
        impact="This outdated function can be exploited to run malicious code. An attacker could use it to gain full access to your website, steal data, or install persistent backdoors.",
        # Metadata
        cwe="CWE-94", recommendation="Use anonymous functions (closures) instead.",
    ),
    # Unsafe callback check
    VulnPattern(
        # ID
        id="PHP-RCE-008", title="call_user_func with variable",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'\bcall_user_func(?:_array)?\s*\(\s*\$',
        # Description
        description="call_user_func with a user-controlled callback enables arbitrary function execution.",
        # Impact
        impact="An attacker could choose which function the server executes, potentially deleting your site content, reading private data, or installing malware.",
        # Metadata
        cwe="CWE-94", recommendation="Validate the callback against a whitelist.",
        # Confidence
        confidence="medium",
    ),

    # ── CRITICAL: Command Injection ──
    # Rules for OS command execution
    VulnPattern(
        # ID for system()
        id="PHP-CMD-001", title="system() call",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'\bsystem\s*\(\s*\$',
        # Description
        description="system() executes an OS command with user-controlled input.",
        # Impact
        impact="An attacker can run operating system commands directly on your server. They could download malware, read your WordPress configuration (including database passwords), delete all your files, or pivot to attack other sites on the same server.",
        # Layman fix
        layman_fix="The plugin is trying to talk directly to your server's operating system using 'system()'. This is very risky. Check if there is a plugin update available that fixes this. If not, consider using a different plugin that doesn't require such deep server access.",
        # Step by step fix
        step_by_step_fix=[
            "Search the file for the `system()` function.",
            "Identify why the plugin is running server-level commands.",
            "Replace the command with a built-in WordPress function (e.g., for file management, use `WP_Filesystem`).",
            "If a command is absolutely necessary, ensure the input is cleaned using `escapeshellarg()`."
        ],
        # Metadata
        cwe="CWE-78", recommendation="Avoid system calls. If required, use escapeshellarg() and a whitelist.",
    ),
    # exec() check
    VulnPattern(
        # ID
        id="PHP-CMD-002", title="exec() call",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'\bexec\s*\(\s*\$',
        # Description
        description="exec() executes an OS command with user-controlled input.",
        # Impact
        impact="An attacker can execute any command on your web server, just as if they were sitting at the keyboard. This means full server compromise — data theft, file deletion, or turning your server into part of a botnet.",
        # Metadata
        cwe="CWE-78", recommendation="Avoid exec(). Use WordPress APIs or escapeshellarg().",
    ),
    # passthru() check
    VulnPattern(
        # ID
        id="PHP-CMD-003", title="passthru() call",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'\bpassthru\s*\(\s*\$',
        # Description
        description="passthru() executes a command and outputs raw results.",
        # Impact
        impact="Attackers can run system commands and see the output directly. This could expose confidential server files, database contents, or allow complete server takeover.",
        # Metadata
        cwe="CWE-78", recommendation="Remove passthru() calls entirely.",
    ),
    # shell_exec() check
    VulnPattern(
        # ID
        id="PHP-CMD-004", title="shell_exec() or backticks",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'\bshell_exec\s*\(\s*\$|`\s*\$[^`]*`',
        # Description
        description="shell_exec() or backtick operator executes shell commands.",
        # Impact
        impact="An attacker gains the ability to execute any command on the server's operating system. This is equivalent to having direct server access and can lead to complete data breach.",
        # Metadata
        cwe="CWE-78", recommendation="Remove shell execution. Use PHP/WordPress native functions.",
    ),
    # popen() check
    VulnPattern(
        # ID
        id="PHP-CMD-005", title="popen() call",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'\bpopen\s*\(\s*\$',
        # Description
        description="popen() opens a process with user-controlled command.",
        # Impact
        impact="Attackers can launch long-running processes on your server — like cryptocurrency miners, spam bots, or tools to attack other websites, all using your server resources.",
        # Metadata
        cwe="CWE-78", recommendation="Avoid popen(). Use WordPress APIs.",
    ),
    # proc_open() check
    VulnPattern(
        # ID
        id="PHP-CMD-006", title="proc_open() call",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'\bproc_open\s*\(',
        # Description
        description="proc_open() can execute arbitrary system commands.",
        # Impact
        impact="This function can be used to run background processes on your server, potentially allowing attackers to install persistent malware that survives plugin updates.",
        # Metadata
        cwe="CWE-78", recommendation="Avoid proc_open() in plugin code.",
    ),

    # ── HIGH: SQL Injection ──
    # Rules for database vulnerabilities
    VulnPattern(
        # ID
        id="PHP-SQLI-001", title="Direct variable in SQL query",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'\$wpdb\s*->\s*(?:query|get_results|get_row|get_var|get_col)\s*\(\s*["\'].*\$',
        # Description
        description="SQL query with direct variable interpolation without $wpdb->prepare().",
        # Impact
        impact="An attacker could read, modify, or delete anything in your database — including user accounts, orders, private messages, and admin credentials. They could also extract sensitive data like email addresses and payment information.",
        # Layman fix
        layman_fix="The code is talking to your database in an 'unprepared' way. To fix this, the developer needs to wrap the query in a '$wpdb->prepare()' function. If you are comfortable editing code, look for '$wpdb->query' and ensure all variables are passed through the prepare method.",
        # Step by step fix
        step_by_step_fix=[
            "Identify the SQL query line in the file.",
            "Locate where variables (like `$id` or `$name`) are being inserted directly into the query string.",
            "Rewrite the query to use placeholders like `%s` (for strings) or `%d` (for numbers).",
            "Pass the actual variables as separate arguments to the `$wpdb->prepare()` function."
        ],
        # Metadata
        cwe="CWE-89", recommendation="Always use $wpdb->prepare() for queries with variables.",
        # False positive check
        false_positive_patterns=(r'\$wpdb\s*->\s*prepare',),
    ),
    # Concatenation check
    VulnPattern(
        # ID
        id="PHP-SQLI-002", title="String concatenation in SQL",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'\$wpdb\s*->\s*(?:query|get_results|get_row|get_var|get_col)\s*\([^)]*\.\s*\$',
        # Description
        description="SQL query built via string concatenation with variables.",
        # Impact
        impact="Attackers can inject their own database commands. This could allow them to dump your entire user table, reset admin passwords, or delete critical data.",
        # Metadata
        cwe="CWE-89", recommendation="Use $wpdb->prepare() with placeholders (%s, %d).",
    ),
    # Raw superglobal check
    VulnPattern(
        # ID
        id="PHP-SQLI-003", title="Raw $_GET/$_POST in SQL",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'\$wpdb\s*->\s*\w+\s*\([^)]*\$_(?:GET|POST|REQUEST)\b',
        # Description
        description="Superglobal variables used directly in SQL queries.",
        # Impact
        impact="User-supplied input is passed directly into a database query with zero filtering. Any visitor to your site could exploit this to steal your entire database or gain admin access.",
        # Metadata
        cwe="CWE-89", recommendation="Sanitize with $wpdb->prepare(), intval(), or sanitize_text_field().",
    ),
    # Unsafe LIKE check
    VulnPattern(
        # ID
        id="PHP-SQLI-004", title="Unsafe LIKE query",
        # Medium
        severity=Severity.MEDIUM,
        # Pattern
        pattern=r'LIKE\s*["\'][^"\']*\$',
        # Description
        description="LIKE clause with variable interpolation. May allow SQL wildcard injection.",
        # Impact
        impact="An attacker could manipulate search queries to extract data they shouldn't have access to, or cause your database to run very slow queries that crash your site.",
        # Metadata
        cwe="CWE-89", recommendation="Use $wpdb->esc_like() before $wpdb->prepare().",
    ),

    # ── HIGH: Cross-Site Scripting (XSS) ──
    # Rules for browser-side script injection
    VulnPattern(
        # ID for unescaped superglobal echo
        id="PHP-XSS-001", title="Unescaped echo of superglobal",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'\becho\s+\$_(?:GET|POST|REQUEST|SERVER|COOKIE)\b',
        # Description
        description="Direct output of superglobal variables without escaping.",
        # Impact
        impact="Attackers can inject malicious scripts that run in your visitors' browsers. This could steal login cookies, redirect users to phishing pages, or display fake login forms that capture passwords.",
        # Layman fix
        layman_fix="The plugin is 'echoing' (printing) data from a user's request without cleaning it first. You can fix this by wrapping the variable in 'esc_html()'. For example, change 'echo $_GET[\"name\"]' to 'echo esc_html($_GET[\"name\"])'.",
        # Step by step fix
        step_by_step_fix=[
            "Find the `echo` statement mentioned in the report.",
            "Identify the variable being displayed (e.g., `$_GET[...]` or `$user_input`).",
            "Wrap that variable in `esc_html()` if it's text, or `esc_attr()` if it's inside an HTML attribute.",
            "Refresh your site and verify the output still looks correct."
        ],
        # Metadata
        cwe="CWE-79", recommendation="Use esc_html(), esc_attr(), or esc_url() before output.",
    ),
    # General variable echo check
    VulnPattern(
        # ID
        id="PHP-XSS-002", title="Unescaped echo of variable",
        # Medium
        severity=Severity.MEDIUM,
        # Pattern
        pattern=r'\becho\s+["\']?[^;]*\$(?!wpdb)\w+',
        # Description
        description="Variable echoed without WordPress escaping functions.",
        # Impact
        impact="Could allow attackers to inject scripts into your pages. Visitors may have their sessions hijacked, see fake content, or be redirected to malicious websites.",
        # Metadata
        cwe="CWE-79", recommendation="Wrap in esc_html(), esc_attr(), or wp_kses().",
        # Confidence
        confidence="medium",
        # False positive check
        false_positive_patterns=(r'esc_html|esc_attr|esc_url|wp_kses|esc_textarea',),
    ),
    # REQUEST_URI check
    VulnPattern(
        # ID
        id="PHP-XSS-003", title="Reflected input via $_SERVER['REQUEST_URI']",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r"""\$_SERVER\s*\[\s*['"]REQUEST_URI['"]\s*\]""",
        # Description
        description="REQUEST_URI can contain user-controlled values; output without escaping causes XSS.",
        # Impact
        impact="A specially crafted URL could inject scripts into your admin pages. If an admin clicks the link, an attacker could take over their account.",
        # Metadata
        cwe="CWE-79", recommendation="Use esc_url() or esc_attr() when outputting.",
        # Confidence
        confidence="medium",
    ),
    # PHP_SELF check
    VulnPattern(
        # ID
        id="PHP-XSS-004", title="Reflected input via $_SERVER['PHP_SELF']",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r"""\$_SERVER\s*\[\s*['"]PHP_SELF['"]\s*\]""",
        # Description
        description="PHP_SELF is user-controllable and can lead to reflected XSS.",
        # Impact
        impact="Attackers can craft malicious links that, when clicked by your users, execute harmful scripts in their browser — potentially stealing their login sessions.",
        # Metadata
        cwe="CWE-79", recommendation="Use esc_url() or admin_url() instead.",
    ),

    # ── HIGH: CSRF ──
    # Rules for Cross-Site Request Forgery
    VulnPattern(
        # ID for missing nonce in form
        id="PHP-CSRF-001", title="Form handler without nonce verification",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'if\s*\(\s*isset\s*\(\s*\$_(?:POST|GET|REQUEST)\b[^)]*\)\s*\)',
        # Description
        description="Form/request handler that checks for submitted data without nonce verification.",
        # Impact
        impact="An attacker could trick a logged-in admin into unknowingly submitting a hidden form — changing plugin settings, creating accounts, or modifying site content without the admin's knowledge.",
        # Metadata
        cwe="CWE-352", recommendation="Add wp_verify_nonce() or check_admin_referer() before processing.",
        # Confidence
        confidence="medium",
        # False positive patterns
        false_positive_patterns=(r'wp_verify_nonce|check_admin_referer|check_ajax_referer',),
    ),
    # AJAX nonce check
    VulnPattern(
        # ID
        id="PHP-CSRF-002", title="AJAX handler without nonce check",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'wp_ajax_(?:nopriv_)?\w+[\s\S]{0,200}?(?:function\s+\w+|[\'\"]\s*,\s*function)',
        # Description
        description="AJAX handler registered without visible nonce verification.",
        # Impact
        impact="Malicious websites could silently trigger actions on your WordPress site while your admin is browsing, potentially changing settings or exfiltrating data.",
        # Metadata
        cwe="CWE-352", recommendation="Use check_ajax_referer() at the start of the handler.",
        # Confidence
        confidence="medium",
    ),

    # ── HIGH: File Inclusion ──
    # Rules for local and remote file inclusion
    VulnPattern(
        # ID for dynamic include
        id="PHP-LFI-001", title="Dynamic include/require with variable",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'\b(?:include|require)(?:_once)?\s*\(\s*\$',
        # Description
        description="File inclusion with a variable path can lead to Local File Inclusion (LFI).",
        # Impact
        impact="An attacker could read any file on your server — including wp-config.php (which contains your database password), private keys, and other sensitive configuration. They might also execute malicious code.",
        # Metadata
        cwe="CWE-98", recommendation="Use a whitelist of allowed files. Never include user-controlled paths.",
    ),
    # file_get_contents check
    VulnPattern(
        # ID
        id="PHP-LFI-002", title="File read with user input",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'\bfile_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)',
        # Description
        description="Reading files based on user input can expose sensitive files.",
        # Impact
        impact="An attacker could read sensitive files like password files, configuration files with database credentials, or private user data stored on the server.",
        # Metadata
        cwe="CWE-22", recommendation="Validate and sanitize file paths. Use a whitelist.",
    ),

    # ── HIGH: File Upload ──
    # Rules for unsafe file uploads
    VulnPattern(
        # ID
        id="PHP-UPLOAD-001", title="Direct move_uploaded_file without validation",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'\bmove_uploaded_file\s*\(',
        # Description
        description="File upload handler detected. Ensure MIME type, extension, and size validation.",
        # Impact
        impact="Without proper validation, an attacker could upload a malicious PHP file disguised as an image, then execute it to gain full control of your website.",
        # Metadata
        cwe="CWE-434", recommendation="Use wp_handle_upload() with strict type checking.",
        # Confidence
        confidence="medium",
    ),

    # ── HIGH: Deserialization ──
    # Rules for insecure object injection
    VulnPattern(
        # ID for unserialize with user input
        id="PHP-DESER-001", title="unserialize() with user input",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
        # Description
        description="Deserializing user input can lead to Object Injection attacks.",
        # Impact
        impact="An attacker can craft special data that, when processed, executes arbitrary code on your server. This can lead to complete site takeover, file deletion, or data theft.",
        # Metadata
        cwe="CWE-502", recommendation="Use json_decode() instead. Never unserialize user input.",
    ),
    # General unserialize check
    VulnPattern(
        # ID
        id="PHP-DESER-002", title="unserialize() usage",
        # Medium
        severity=Severity.MEDIUM,
        # Pattern
        pattern=r'\bunserialize\s*\(\s*\$',
        # Description
        description="unserialize() with variable input. Verify the source is trusted.",
        # Impact
        impact="If the data source is compromised, attackers could exploit this to execute code on your server or manipulate your site's behavior.",
        # Metadata
        cwe="CWE-502", recommendation="Prefer json_decode(). If unserialize is needed, use allowed_classes option.",
        # Confidence
        confidence="medium",
    ),

    # ── MEDIUM: Authentication / Authorization ──
    # Rules for permission checking
    VulnPattern(
        # ID for missing capability check
        id="PHP-AUTH-001", title="Missing capability check",
        # Medium
        severity=Severity.MEDIUM,
        # Pattern
        pattern=r'(?:add_action|add_filter)\s*\(\s*[\'"](?:wp_ajax_|admin_)',
        # Description
        description="Admin/AJAX action registered. Ensure current_user_can() is checked.",
        # Impact
        impact="Without proper permission checks, any logged-in user — even subscribers — could access admin-only functionality, potentially modifying settings, viewing private data, or escalating their privileges.",
        # Metadata
        cwe="CWE-862", recommendation="Add current_user_can() check at the start of the callback.",
        # Confidence
        confidence="medium",
        # False positive patterns
        false_positive_patterns=(r'current_user_can',),
    ),
    # is_admin check
    VulnPattern(
        # ID
        id="PHP-AUTH-002", title="is_admin() used for authorization",
        # Medium
        severity=Severity.MEDIUM,
        # Pattern
        pattern=r'\bis_admin\s*\(\s*\)',
        # Description
        description="is_admin() checks if on an admin page, NOT if the user is an admin.",
        # Impact
        impact="Developers often misuse this as a security check. Regular users who somehow access admin pages would bypass this check, potentially accessing sensitive functionality.",
        # Metadata
        cwe="CWE-862", recommendation="Use current_user_can('manage_options') for authorization.",
        # Low confidence
        confidence="low",
    ),
    # REST route permission callback check
    VulnPattern(
        # ID
        id="PHP-AUTH-003", title="REST route exposed with __return_true permission callback",
        # High severity because unauthenticated REST endpoints are a frequent exploitation path
        severity=Severity.HIGH,
        # Match explicit public permission callbacks in route definitions
        pattern=r'''[\'\"]permission_callback[\'\"]\s*=>\s*[\'\"]?__return_true[\'\"]?''',
        # Description
        description="REST API route allows access to everyone via permission_callback => __return_true.",
        # Impact
        impact="If this endpoint performs state-changing actions, attackers may be able to modify site settings, create content, or expose sensitive data without logging in. Public REST endpoints are a common source of WordPress plugin vulnerabilities.",
        # Layman fix
        layman_fix="The plugin is making a WordPress API endpoint public to everyone. The developer should review whether this endpoint really needs to be public and, if not, add a proper permission check.",
        # Technical checklist
        step_by_step_fix=[
            "Locate the register_rest_route() call referenced in the report.",
            "Review what the endpoint does and whether anonymous access is actually required.",
            "Replace __return_true with a permission_callback that checks user capabilities or validates a nonce/token.",
            "Add tests for both authorized and unauthorized requests."
        ],
        # Metadata
        cwe="CWE-862", recommendation="Use a permission_callback that enforces capability or token checks.",
        # Confidence
        confidence="medium",
    ),

    # ── MEDIUM: Open Redirect ──
    # Rules for phishing redirects
    VulnPattern(
        # ID
        id="PHP-REDIR-001", title="Unsafe redirect with user input",
        # Medium
        severity=Severity.MEDIUM,
        # Pattern
        pattern=r'\bwp_redirect\s*\(\s*\$_(?:GET|POST|REQUEST)',
        # Description
        description="Redirect destination from user input can be exploited for phishing.",
        # Impact
        impact="An attacker could craft a link that appears to be on your site but redirects visitors to a fake login page that steals their credentials.",
        # Metadata
        cwe="CWE-601", recommendation="Use wp_safe_redirect() and wp_validate_redirect().",
    ),
    # header() redirect check
    VulnPattern(
        # ID
        id="PHP-REDIR-002", title="header() redirect with variable",
        # Medium
        severity=Severity.MEDIUM,
        # Pattern
        pattern=r'\bheader\s*\(\s*["\']Location:\s*["\']?\s*\.\s*\$',
        # Description
        description="PHP header redirect with unsanitized variable.",
        # Impact
        impact="Users could be silently redirected to phishing sites or malware downloads through crafted URLs shared via email or social media.",
        # Metadata
        cwe="CWE-601", recommendation="Use wp_safe_redirect() instead of header().",
    ),

    # ── MEDIUM: Information Disclosure ──
    # Rules for configuration leakage
    VulnPattern(
        # ID for phpinfo()
        id="PHP-INFO-001", title="phpinfo() call",
        # Medium
        severity=Severity.MEDIUM,
        # Pattern
        pattern=r'\bphpinfo\s*\(',
        # Description
        description="phpinfo() exposes sensitive server configuration details.",
        # Impact
        impact="Reveals your server's PHP version, installed modules, file paths, and environment variables to anyone who can access it — providing attackers with a detailed roadmap for targeting your specific setup.",
        # Metadata
        cwe="CWE-200", recommendation="Remove phpinfo() calls from production code.",
    ),
    # Error display check
    VulnPattern(
        # ID
        id="PHP-INFO-002", title="Error display enabled",
        # Low
        severity=Severity.LOW,
        # Pattern
        pattern=r'(?:ini_set|error_reporting)\s*\([^)]*(?:E_ALL|display_errors)',
        # Description
        description="Debug error display should not be in production code.",
        # Impact
        impact="Detailed error messages can reveal database table names, file paths, and code structure to attackers, making it easier for them to find and exploit other vulnerabilities.",
        # Metadata
        cwe="CWE-209", recommendation="Remove debug error settings. Use WP_DEBUG only in development.",
    ),
    # var_dump check
    VulnPattern(
        # ID
        id="PHP-INFO-003", title="var_dump/print_r in production",
        # Low
        severity=Severity.LOW,
        # Pattern
        pattern=r'\b(?:var_dump|print_r|var_export)\s*\(\s*\$',
        # Description
        description="Debug output functions should not appear in production code.",
        # Impact
        impact="Debug output may accidentally expose sensitive data like user information, API keys, or internal system details to website visitors.",
        # Metadata
        cwe="CWE-200", recommendation="Remove debug output before release.",
    ),

    # ── MEDIUM: Cryptographic Issues ──
    # Rules for weak crypto or hardcoded keys
    VulnPattern(
        # ID for MD5
        id="PHP-CRYPTO-001", title="MD5 used for security purposes",
        # Medium
        severity=Severity.MEDIUM,
        # Pattern
        pattern=r'\bmd5\s*\(\s*\$(?!file)',
        # Description
        description="MD5 is cryptographically broken for security use (passwords, tokens).",
        # Impact
        impact="Passwords hashed with MD5 can be cracked in seconds using modern hardware. If your database is breached, all user passwords would be immediately exposed.",
        # Metadata
        cwe="CWE-328", recommendation="Use wp_hash_password() or password_hash() for passwords.",
        # Confidence
        confidence="medium",
    ),
    # SHA1 check
    VulnPattern(
        # ID
        id="PHP-CRYPTO-002", title="SHA1 used for security purposes",
        # Medium
        severity=Severity.MEDIUM,
        # Pattern
        pattern=r'\bsha1\s*\(\s*\$',
        # Description
        description="SHA1 is considered weak for security-critical operations.",
        # Impact
        impact="SHA1 has known collision attacks. Security tokens or password hashes using SHA1 can potentially be forged or cracked faster than with modern algorithms.",
        # Metadata
        cwe="CWE-328", recommendation="Use hash('sha256', ...) or WordPress native hashing.",
        # Confidence
        confidence="medium",
    ),
    # Hardcoded secret check
    VulnPattern(
        # ID
        id="PHP-CRYPTO-003", title="Hardcoded cryptographic key",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r"""(?:secret|key|password|token|api_key|apikey)\s*(?:=|=>)\s*['"][A-Za-z0-9+/=]{8,}['"]""",
        # Description
        description="Hardcoded secrets in source code can be extracted by attackers.",
        # Impact
        impact="Anyone who can view the plugin code (including from the WordPress plugin repository) can see these credentials. This could give attackers access to third-party services, payment processors, or your site's API endpoints.",
        # Metadata
        cwe="CWE-798", recommendation="Use wp_options, environment variables, or wp-config.php constants.",
        # Confidence
        confidence="medium",
    ),

    # ── CRITICAL: Backdoor / Malware Indicators ──
    # Highly specific malware signatures
    VulnPattern(
        # ID for obfuscation chain
        id="PHP-MALWARE-001", title="Base64 decode + eval chain",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'(?:eval|assert|system|exec)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)\s*\(',
        # Description
        description="Multi-layer obfuscation chain — strong indicator of a backdoor.",
        # Impact
        impact="This is a classic malware signature. The code is deliberately hidden to avoid detection. Your site is very likely compromised and may be actively being used to attack visitors, send spam, or steal data.",
        # Metadata
        cwe="CWE-506", recommendation="Remove immediately. Audit the full plugin for compromise.",
    ),
    # Long base64 check
    VulnPattern(
        # ID
        id="PHP-MALWARE-002", title="Suspicious long base64 string",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r"""['"][A-Za-z0-9+/]{100,}={0,2}['"]""",
        # Description
        description="Very long base64-encoded string, often used to hide malicious payloads.",
        # Impact
        impact="Large encoded strings are commonly used to hide malware. The hidden content could be a webshell, spam injector, or data-stealing script that activates without your knowledge.",
        # Metadata
        cwe="CWE-506", recommendation="Decode and inspect the content. Remove if malicious.",
        # Confidence
        confidence="medium",
    ),
    # Hex execution check
    VulnPattern(
        # ID
        id="PHP-MALWARE-003", title="Hex-encoded string execution",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'(?:eval|assert)\s*\(\s*(?:pack\s*\(\s*["\']H\*["\']|hex2bin)',
        # Description
        description="Hex-encoded payload executed dynamically — malware indicator.",
        # Impact
        impact="Code is being hidden using hexadecimal encoding to avoid detection. This is a telltale sign of malware that could be doing anything from stealing data to creating backdoor accounts.",
        # Metadata
        cwe="CWE-506", recommendation="Remove immediately.",
    ),
    # Remote file access check
    VulnPattern(
        # ID
        id="PHP-MALWARE-004", title="Remote file access via URL",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'(?:file_get_contents|fopen|include|require)\s*\(\s*["\']https?://',
        # Description
        description="Loading remote content/code can introduce malware or exfiltrate data.",
        # Impact
        impact="The plugin is downloading content from external servers. This could be used to load malware updates, send your site's data to third parties, or inject advertising/spam content that changes over time.",
        # Metadata
        cwe="CWE-829", recommendation="Use WordPress HTTP API (wp_remote_get) with URL validation.",
        # Confidence
        confidence="medium",
    ),
    # Webshell check
    VulnPattern(
        # ID
        id="PHP-MALWARE-005", title="Webshell pattern: $_GET/$_POST in eval/exec",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'(?:eval|assert|system|exec|passthru|shell_exec)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
        # Description
        description="Classic webshell: direct execution of user-supplied input.",
        # Impact
        impact="This is a live webshell — it allows anyone who knows the URL to execute any command on your server. Your site is compromised. Attackers have full control and may have already stolen data or installed additional backdoors.",
        # Metadata
        cwe="CWE-94", recommendation="Remove immediately. The plugin is compromised.",
    ),
    # Hidden admin check
    VulnPattern(
        # ID
        id="PHP-MALWARE-006", title="Hidden admin user creation",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'wp_(?:create_user|insert_user)\s*\(',
        # Description
        description="User creation in plugin code. Verify this is intentional and authorized.",
        # Impact
        impact="Malware commonly creates hidden administrator accounts so attackers can log into your WordPress dashboard at any time — even after you remove the malicious plugin.",
        # Metadata
        cwe="CWE-506", recommendation="Audit the context. Malware often creates hidden admin accounts.",
        # Confidence
        confidence="medium",
    ),
    # chr() string building check
    VulnPattern(
        # ID
        id="PHP-MALWARE-007", title="Suspicious chr() string building",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'(?:chr\s*\(\s*\d+\s*\)\s*\.?\s*){5,}',
        # Description
        description="Building strings via chr() calls — common obfuscation to hide malicious code.",
        # Impact
        impact="The code is deliberately obscured character by character. This is a common technique to hide malicious function names and URLs from security scanners and human reviewers.",
        # Metadata
        cwe="CWE-506", recommendation="Decode and inspect the constructed string.",
    ),
    # rot13 check
    VulnPattern(
        # ID
        id="PHP-MALWARE-008", title="str_rot13 obfuscation",
        # Medium
        severity=Severity.MEDIUM,
        # Pattern
        pattern=r'\bstr_rot13\s*\(\s*["\']',
        # Description
        description="ROT13 used to obfuscate strings — sometimes used to hide malicious intent.",
        # Impact
        impact="While ROT13 is a simple encoding, its use in a WordPress plugin is unusual and may indicate an attempt to hide malicious URLs, function calls, or other suspicious content from reviewers.",
        # Metadata
        cwe="CWE-506", recommendation="Decode and inspect. Remove if concealing harmful code.",
        # Confidence
        confidence="medium",
    ),
    # cURL exfiltration check
    VulnPattern(
        # ID
        id="PHP-MALWARE-009", title="Data exfiltration via cURL",
        # High
        severity=Severity.HIGH,
        # Pattern
        pattern=r'curl_setopt\s*\([^)]*CURLOPT_POSTFIELDS\s*,[^)]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)',
        # Description
        description="Sending superglobal data to external servers — possible data exfiltration.",
        # Impact
        impact="Your visitors' personal data (IP addresses, form submissions, cookies) may be secretly sent to external servers controlled by attackers. This is a serious privacy violation and potential GDPR/legal issue.",
        # Metadata
        cwe="CWE-200", recommendation="Remove and audit what data is being transmitted.",
    ),
    # Miner check
    VulnPattern(
        # ID for miners
        id="PHP-MALWARE-010", title="Cryptocurrency miner pattern",
        # Critical
        severity=Severity.CRITICAL,
        # Pattern
        pattern=r'(?:coinhive|cryptonight|minero|coin-hive|CoinImp)',
        # Description
        description="Cryptocurrency miner code detected — unauthorized resource usage.",
        # Impact
        impact="Your visitors' computers and phones are being secretly used to mine cryptocurrency for the attacker. This slows down their devices, drains batteries, increases electricity costs, and can damage your site's reputation and SEO ranking.",
        # Metadata
        cwe="CWE-506", recommendation="Remove immediately.",
        # High confidence
        confidence="high",
    ),
    VulnPattern(
        id="PHP-MALWARE-011", title="Decoded payload executed through variable function",
        severity=Severity.CRITICAL,
        pattern=r'\$\w+\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|hex2bin)\s*\(',
        description="A variable function or callback executes a decoded payload. This is a common backdoor evasion technique.",
        impact="The plugin may be hiding malicious code behind indirection so simpler scanners and manual review miss the execution path.",
        cwe="CWE-506",
        recommendation="Treat as highly suspicious, decode the payload, and remove the backdoor.",
        confidence="high",
    ),
    VulnPattern(
        id="PHP-MALWARE-012", title="Error-suppressed dangerous execution",
        severity=Severity.HIGH,
        pattern=r'@\s*(?:eval|assert|system|exec|passthru|shell_exec|base64_decode|gzinflate)\s*\(',
        description="Error suppression on dangerous execution or decoding functions is often used to hide malicious behavior.",
        impact="Hidden execution paths can stay unnoticed during testing while still activating in production, which makes malware or backdoors harder to detect.",
        cwe="CWE-506",
        recommendation="Remove error suppression and review why the dangerous function is needed at all.",
        confidence="medium",
    ),
    VulnPattern(
        id="PHP-MALWARE-013", title="User input assigned to variable variables",
        severity=Severity.HIGH,
        pattern=r'(?:\$\$\w+|\$\w+\s*=\s*\$\$\w+)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)',
        description="Variable-variable assignment from user input can rewire execution flow or smuggle attacker-controlled values into sensitive variables.",
        impact="Attackers may overwrite internal variables, bypass logic, or prepare data that later reaches dangerous sinks such as eval, include, or SQL queries.",
        cwe="CWE-94",
        recommendation="Avoid variable variables and map request input explicitly to known fields.",
        confidence="medium",
    ),
    VulnPattern(
        id="PHP-MALWARE-014", title="Suspicious outbound request with request data",
        severity=Severity.HIGH,
        pattern=r'(?:wp_remote_post\s*\(|curl_setopt\s*\([^)]*CURLOPT_POSTFIELDS\s*,)[^\n;]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)',
        description="Request or server data is being forwarded to a remote endpoint, which can indicate telemetry abuse or data exfiltration.",
        impact="Visitor information, cookies, tokens, or form submissions may be sent to third-party servers without authorization.",
        cwe="CWE-200",
        recommendation="Audit the remote destination and strip sensitive data from outbound requests.",
        confidence="medium",
    ),

    # ── LOW: Best Practice Violations ──
    # Non-critical quality checks
    VulnPattern(
        id="PHP-BP-001", title="Direct use of $_GET/$_POST without sanitization",
        severity=Severity.LOW,
        pattern=r'\$_(?:GET|POST|REQUEST)\s*\[\s*[\'\"][^\]]+[\'\"]\s*\](?!\s*\))',
        description="Superglobal used without immediate sanitization.",
        impact="User input is being used without cleaning it first. While not always exploitable on its own, this is poor practice that makes other vulnerabilities (like XSS or SQL injection) more likely.",
        cwe="CWE-20",
        recommendation="Wrap in sanitize_text_field(), intval(), or absint().",
        confidence="low",
    ),
    VulnPattern(
        id="PHP-BP-002", title="extract() usage",
        severity=Severity.MEDIUM,
        pattern=r'\bextract\s*\(\s*\$',
        description="extract() imports variables into scope, risking variable overwrite attacks.",
        impact="An attacker could potentially overwrite important internal variables, bypassing security checks or changing the plugin's behavior in unexpected ways.",
        cwe="CWE-621",
        recommendation="Access array values directly instead of using extract().",
    ),
    VulnPattern(
        id="PHP-BP-003", title="Deprecated MySQL functions",
        severity=Severity.LOW,
        pattern=r'\bmysql_(?:query|connect|select_db|fetch)\s*\(',
        description="Deprecated mysql_* functions. WordPress uses $wpdb internally.",
        impact="These outdated database functions lack modern security features. Using them indicates the code hasn't been maintained and may be vulnerable to SQL injection attacks.",
        cwe="CWE-477",
        recommendation="Use $wpdb methods instead of raw MySQL functions.",
    ),
    VulnPattern(
        id="PHP-BP-004", title="Use of $_REQUEST superglobal",
        severity=Severity.LOW,
        pattern=r'\b\$_REQUEST\b',
        description="$_REQUEST merges GET, POST, and COOKIE data and can cause unexpected input handling or security bypasses.",
        impact="Attackers might supply data through an unexpected channel such as cookies when the code intended to only trust form or query-string input.",
        layman_fix="The developer should replace $_REQUEST with the more specific $_GET or $_POST and sanitize the value immediately.",
        step_by_step_fix=[
            "Find where `$_REQUEST` is referenced.",
            "Decide whether the data should come from GET or POST.",
            "Replace `$_REQUEST` with the specific superglobal.",
            "Apply input sanitization such as `sanitize_text_field()`, `absint()`, or `sanitize_key()`."
        ],
        cwe="CWE-20",
        recommendation="Prefer $_GET or $_POST explicitly and sanitize as close to input as possible.",
        confidence="high",
    ),
]

# ─── JAVASCRIPT VULNERABILITY PATTERNS ──────────────────────────────
# Collection of security signatures targeting JavaScript/TypeScript
JS_PATTERNS: list[VulnPattern] = [
    VulnPattern(
        id="JS-XSS-001", title="innerHTML assignment with variable",
        severity=Severity.MEDIUM,
        pattern=r'\.innerHTML\s*=\s*(?![\s]*["\']<)',
        description="Setting innerHTML with dynamic content can introduce DOM-based XSS.",
        impact="An attacker could inject malicious scripts into your page that steal visitor data, hijack sessions, or redirect users to dangerous websites.",
        cwe="CWE-79",
        recommendation="Use textContent or DOMPurify.sanitize().",
        languages=("js", "jsx", "ts", "tsx"),
    ),
    VulnPattern(
        id="JS-XSS-002", title="document.write() usage",
        severity=Severity.MEDIUM,
        pattern=r'\bdocument\.write\s*\(',
        description="document.write() can introduce XSS and degrades performance.",
        impact="Attackers could inject content directly into your page. Visitors might see fake forms, malicious downloads, or be redirected without warning.",
        cwe="CWE-79",
        recommendation="Use DOM manipulation methods instead.",
        languages=("js", "jsx", "ts", "tsx"),
    ),
    VulnPattern(
        id="JS-RCE-001", title="eval() in JavaScript",
        severity=Severity.HIGH,
        pattern=r'\beval\s*\(',
        description="eval() executes arbitrary JavaScript — major security risk.",
        impact="If an attacker can control what gets evaluated, they can run any JavaScript in your users' browsers — stealing cookies, form data, or redirecting to malicious sites.",
        cwe="CWE-94",
        recommendation="Use JSON.parse() or Function() with extreme caution.",
        languages=("js", "jsx", "ts", "tsx"),
    ),
    VulnPattern(
        id="JS-MALWARE-001", title="eval(atob()) obfuscated JavaScript payload",
        severity=Severity.HIGH,
        pattern=r'\beval\s*\(\s*(?:atob|window\.atob)\s*\(',
        description="Base64-decoded content is executed dynamically in JavaScript. This is a strong malware and skimmer indicator.",
        impact="Malicious scripts can be hidden inside encoded blobs and only decoded in the browser, helping attackers steal data while evading basic review.",
        cwe="CWE-506",
        recommendation="Remove encoded dynamic execution and replace it with transparent, static logic.",
        languages=("js", "jsx", "ts", "tsx"),
        confidence="high",
    ),
    VulnPattern(
        id="JS-RCE-002", title="Function() constructor",
        severity=Severity.HIGH,
        pattern=r'\bnew\s+Function\s*\(',
        description="Function constructor is equivalent to eval() and poses the same risks.",
        impact="Similar to eval(), this can be exploited to run arbitrary JavaScript, potentially stealing user data or hijacking browsing sessions.",
        cwe="CWE-94",
        recommendation="Refactor to avoid dynamic code generation.",
        languages=("js", "jsx", "ts", "tsx"),
    ),
    VulnPattern(
        id="JS-MALWARE-002", title="Obfuscated String.fromCharCode payload",
        severity=Severity.MEDIUM,
        pattern=r'(?:String\.)?fromCharCode\s*\((?:\s*\d+\s*,){5,}\s*\d+\s*\)',
        description="Large String.fromCharCode chains are often used to hide malicious JavaScript payloads or skimmers.",
        impact="Obfuscated browser-side payloads can steal checkout details, inject ads, or redirect users while appearing harmless during source review.",
        cwe="CWE-506",
        recommendation="Decode the payload and replace it with readable, auditable source code.",
        languages=("js", "jsx", "ts", "tsx"),
        confidence="medium",
    ),
    VulnPattern(
        id="JS-AJAX-001", title="AJAX call without nonce",
        severity=Severity.MEDIUM,
        pattern=r'(?:jQuery\.(?:ajax|post|get)|fetch|XMLHttpRequest).*admin-ajax\.php',
        description="AJAX call to WordPress without nonce parameter.",
        impact="Without a security token, other websites could trick your visitors' browsers into making requests to your WordPress site, potentially changing settings or triggering actions without consent.",
        cwe="CWE-352",
        recommendation="Include wp_nonce in AJAX requests using wp_create_nonce().",
        languages=("js", "jsx", "ts", "tsx"),
        confidence="medium",
    ),
    VulnPattern(
        id="JS-PROTO-001", title="Prototype pollution risk",
        severity=Severity.MEDIUM,
        pattern=r'(?:__proto__|constructor\s*\[\s*["\']prototype["\']\s*\])',
        description="Potential prototype pollution vector.",
        impact="An attacker could modify how JavaScript objects behave globally, potentially bypassing security checks, causing the application to crash, or injecting malicious behavior.",
        cwe="CWE-1321",
        recommendation="Validate object keys. Use Object.create(null) for dictionaries.",
        languages=("js", "jsx", "ts", "tsx"),
    ),
    VulnPattern(
        id="JS-EXT-001", title="External script loading",
        severity=Severity.MEDIUM,
        pattern=r'(?:createElement\s*\(\s*["\']script["\']|\.src\s*=\s*["\']https?://)',
        description="Dynamic loading of external scripts can introduce supply-chain risks.",
        impact="If the external server is compromised, malicious JavaScript could be loaded onto your site without any changes to your own code — affecting all your visitors silently.",
        cwe="CWE-829",
        recommendation="Load scripts via wp_enqueue_script() with integrity checks.",
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

