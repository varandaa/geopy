// Policy Security Scanner
// A single-file Go tool that audits codebases for dangerous patterns in Python source,
// secrets in GitHub Actions workflows, database files, and general configuration files.
//
// Usage:
//   go run scanner.go [flags] <path>
//
// Flags:
//   -path string      Root path to scan (default ".")
//   -json             Output results as JSON
//   -severity string  Minimum severity to report: low|medium|high|critical (default "low")
//   -no-color         Disable ANSI color output
//   -workers int      Number of parallel workers (default 4)
//   -out string       Write report to file instead of stdout
//
// Build:
//   go build -o scanner scanner.go

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

type Severity int

const (
	SevLow      Severity = 1
	SevMedium   Severity = 2
	SevHigh     Severity = 3
	SevCritical Severity = 4
)

func (s Severity) String() string {
	switch s {
	case SevLow:
		return "LOW"
	case SevMedium:
		return "MEDIUM"
	case SevHigh:
		return "HIGH"
	case SevCritical:
		return "CRITICAL"
	}
	return "UNKNOWN"
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func parseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SevCritical
	case "high":
		return SevHigh
	case "medium":
		return SevMedium
	default:
		return SevLow
	}
}

type Category string

const (
	CatSecret       Category = "SECRET"
	CatInjection	Category = "CODE_INJECTION"
	CatDangerous    Category = "DANGEROUS_CODE"
	CatHardcoded    Category = "HARDCODED_VALUE"
	CatCrypto       Category = "WEAK_CRYPTO"
	CatPermission   Category = "INSECURE_PERMISSION"
	CatSupplyChain  Category = "SUPPLY_CHAIN"
	CatInfoDisclose Category = "INFO_DISCLOSURE"
	CatMiscConfig   Category = "MISC_CONFIG"
)

type Finding struct {
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Column     int      `json:"column,omitempty"`
	Severity   Severity `json:"severity"`
	Category   Category `json:"category"`
	RuleID     string   `json:"rule_id"`
	Title      string   `json:"title"`
	Detail     string   `json:"detail"`
	Snippet    string   `json:"snippet,omitempty"`
	Remediation string  `json:"remediation,omitempty"`
}

type ScanResult struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	RootPath   string    `json:"root_path"`
	FilesTotal int       `json:"files_total"`
	FilesScanned int     `json:"files_scanned"`
	Findings   []Finding `json:"findings"`
	Stats      map[string]int `json:"stats"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule engine
// ─────────────────────────────────────────────────────────────────────────────

type RegexRule struct {
	ID          string
	Pattern     *regexp.Regexp
	Severity    Severity
	Category    Category
	Title       string
	Detail      string
	Remediation string
	// When true, the rule is only triggered when the match is NOT inside a comment
	SkipComments bool
}

// Python dangerous pattern rules
var pythonRules = []RegexRule{
	{
		ID: "PY001", Severity: SevCritical, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)\beval\s*\(`),
		Title:       "Use of eval()",
		Detail:      "eval() executes arbitrary Python code from a string. Attacker-controlled input can lead to Remote Code Execution.",
		Remediation: "Replace eval() with ast.literal_eval() for safe data parsing, or refactor to avoid dynamic execution.",
		SkipComments: true,
	},
	{
		ID: "PY002", Severity: SevCritical, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)\bexec\s*\(`),
		Title:       "Use of exec()",
		Detail:      "exec() executes arbitrary Python code. Extremely dangerous with untrusted input.",
		Remediation: "Avoid exec(). Refactor to use explicit function calls or importlib for dynamic loading.",
		SkipComments: true,
	},
	{
		ID: "PY003", Severity: SevHigh, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)\bcompile\s*\(.*\beval\b`),
		Title:       "compile() with eval mode",
		Detail:      "compile() in eval mode followed by exec/eval can execute arbitrary code.",
		Remediation: "Avoid compiling untrusted strings for execution.",
	},
	{
		ID: "PY004", Severity: SevHigh, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)\b__import__\s*\(`),
		Title:       "Dynamic import via __import__()",
		Detail:      "Dynamic imports with user-controlled strings can load arbitrary modules.",
		Remediation: "Use importlib.import_module() with a strict allowlist of permitted module names.",
	},
	{
		ID: "PY005", Severity: SevHigh, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)\bimportlib\.import_module\s*\(`),
		Title:       "Dynamic module import",
		Detail:      "importlib.import_module() with untrusted input allows loading arbitrary code.",
		Remediation: "Validate module name against an explicit allowlist before importing.",
	},
	{
		ID: "PY006", Severity: SevHigh, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)(subprocess\.(call|run|Popen|check_output|check_call))\s*\(`),
		Title:       "Subprocess execution",
		Detail:      "Subprocess calls with shell=True or unsanitised input can lead to command injection.",
		Remediation: "Use shell=False, pass arguments as a list, and validate all inputs. Prefer specific libraries over shelling out.",
	},
	{
		ID: "PY007", Severity: SevCritical, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)subprocess\.[a-z_]+\s*\([^)]*shell\s*=\s*True`),
		Title:       "subprocess with shell=True",
		Detail:      "shell=True passes the command to the system shell, enabling injection via metacharacters.",
		Remediation: "Pass the command as a list and set shell=False (the default).",
	},
	{
		ID: "PY008", Severity: SevHigh, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)\bos\.(system|popen|execv|execve|execvp|spawnl|spawnle)\s*\(`),
		Title:       "Dangerous os module call",
		Detail:      "os.system/popen/exec* functions execute shell commands and are vulnerable to injection.",
		Remediation: "Use subprocess with shell=False and explicit argument lists.",
	},
	{
		ID: "PY009", Severity: SevMedium, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)\bpickle\.(loads?|load)\s*\(`),
		Title:       "Insecure deserialization via pickle",
		Detail:      "pickle.load/loads executes arbitrary Python code during deserialization. Never unpickle untrusted data.",
		Remediation: "Use JSON, msgpack, or another safe serialization format. If pickle is required, cryptographically sign payloads.",
	},
	{
		ID: "PY010", Severity: SevMedium, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)\b(marshal|shelve|yaml\.load)\s*\(`),
		Title:       "Potentially unsafe deserialization",
		Detail:      "marshal, shelve, and yaml.load (without Loader=yaml.SafeLoader) can execute arbitrary code.",
		Remediation: "Use yaml.safe_load() for YAML. Avoid marshal/shelve with untrusted data.",
	},
	{
		ID: "PY011", Severity: SevHigh, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)\byaml\.load\s*\([^)]*\)`),
		Title:       "yaml.load() without SafeLoader",
		Detail:      "yaml.load() without an explicit Loader can deserialize Python objects, leading to RCE.",
		Remediation: "Replace with yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
	},
	{
		ID: "PY012", Severity: SevHigh, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)\b(cursor\.execute|db\.execute|conn\.execute)\s*\(\s*[f"'].*%`),
		Title:       "Possible SQL injection via string formatting",
		Detail:      "Building SQL queries with string formatting or % operator allows SQL injection.",
		Remediation: "Use parameterised queries: cursor.execute('SELECT * FROM t WHERE id = %s', (id,))",
	},
	{
		ID: "PY013", Severity: SevHigh, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)(execute|raw)\s*\(\s*f["']`),
		Title:       "f-string in SQL/ORM execute call",
		Detail:      "f-strings in database execute calls are a SQL injection vector.",
		Remediation: "Use bound parameters instead of string interpolation.",
	},
	{
		ID: "PY014", Severity: SevMedium, Category: CatCrypto,
		Pattern:     regexp.MustCompile(`(?i)\bhashlib\.(md5|sha1)\s*\(`),
		Title:       "Weak hash algorithm (MD5/SHA1)",
		Detail:      "MD5 and SHA1 are cryptographically broken and should not be used for security-sensitive purposes.",
		Remediation: "Use hashlib.sha256() or hashlib.sha3_256() for general hashing; use bcrypt/argon2 for passwords.",
	},
	{
		ID: "PY015", Severity: SevHigh, Category: CatCrypto,
		Pattern:     regexp.MustCompile(`(?i)\bDES\b|DES3|RC4|RC2\b`),
		Title:       "Weak cipher algorithm",
		Detail:      "DES, 3DES, RC4, and RC2 are deprecated ciphers with known weaknesses.",
		Remediation: "Use AES-256-GCM or ChaCha20-Poly1305.",
	},
	{
		ID: "PY016", Severity: SevMedium, Category: CatCrypto,
		Pattern:     regexp.MustCompile(`(?i)\brandom\.(random|randint|choice|shuffle|seed)\s*\(`),
		Title:       "Insecure random number generation",
		Detail:      "The random module is not cryptographically secure and must not be used for secrets, tokens, or keys.",
		Remediation: "Use secrets module (secrets.token_bytes, secrets.token_hex) or os.urandom() for security-sensitive randomness.",
	},
	{
		ID: "PY017", Severity: SevHigh, Category: CatDangerous,
		Pattern:     regexp.MustCompile(`(?i)\bctypes\.(cdll|windll|oledll|pydll)\.LoadLibrary\s*\(`),
		Title:       "Dynamic native library loading",
		Detail:      "Loading native libraries at runtime from attacker-controlled paths can lead to DLL/SO hijacking.",
		Remediation: "Hardcode library paths and validate them against an allowlist.",
	},
	{
		ID: "PY018", Severity: SevMedium, Category: CatDangerous,
		Pattern:     regexp.MustCompile(`(?i)\bgetattr\s*\([^,]+,\s*[^,)]+\)`),
		Title:       "Dynamic attribute access via getattr()",
		Detail:      "getattr() with user-controlled attribute names allows accessing arbitrary object attributes.",
		Remediation: "Validate attribute names against an explicit allowlist before calling getattr().",
	},
	{
		ID: "PY019", Severity: SevMedium, Category: CatPermission,
		Pattern:     regexp.MustCompile(`(?i)\bos\.chmod\s*\([^,]+,\s*0o?777`),
		Title:       "World-writable file permission (777)",
		Detail:      "Setting permissions to 777 makes files writable by all users, enabling tampering.",
		Remediation: "Use the minimum necessary permissions (e.g., 0o644 for files, 0o755 for executables).",
	},
	{
		ID: "PY020", Severity: SevMedium, Category: CatDangerous,
		Pattern:     regexp.MustCompile(`(?i)\btempfile\.(mktemp)\s*\(`),
		Title:       "Insecure temporary file creation (mktemp)",
		Detail:      "tempfile.mktemp() is vulnerable to TOCTOU race conditions. The file can be replaced between creation and use.",
		Remediation: "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.",
	},
	{
		ID: "PY021", Severity: SevHigh, Category: CatDangerous,
		Pattern:     regexp.MustCompile(`(?i)\b(requests\.get|requests\.post|urllib\.request\.urlopen)\s*\([^)]*verify\s*=\s*False`),
		Title:       "TLS certificate verification disabled",
		Detail:      "Disabling TLS verification makes the connection vulnerable to man-in-the-middle attacks.",
		Remediation: "Remove verify=False. If using a private CA, pass the CA bundle path: verify='/path/to/ca-bundle.crt'",
	},
	{
		ID: "PY022", Severity: SevMedium, Category: CatDangerous,
		Pattern:     regexp.MustCompile(`(?i)\bssl\._create_unverified_context\s*\(`),
		Title:       "SSL unverified context created",
		Detail:      "ssl._create_unverified_context() disables certificate verification globally for the context.",
		Remediation: "Use ssl.create_default_context() which validates certificates by default.",
	},
	{
		ID: "PY023", Severity: SevLow, Category: CatInfoDisclose,
		Pattern:     regexp.MustCompile(`(?i)\btraceback\.print_exc\s*\(\s*\)|traceback\.format_exc\s*\(\s*\)`),
		Title:       "Full traceback exposed to output",
		Detail:      "Printing full tracebacks can leak internal paths, library versions, and logic to users.",
		Remediation: "Log tracebacks internally (e.g., logging.exception()) and return generic error messages to users.",
	},
	{
		ID: "PY024", Severity: SevMedium, Category: CatDangerous,
		Pattern:     regexp.MustCompile(`(?i)\bsocket\.setdefaulttimeout\s*\(\s*None\s*\)|socket\.setdefaulttimeout\s*\(\s*0\s*\)`),
		Title:       "Socket with no timeout",
		Detail:      "Sockets with no timeout can hang indefinitely, enabling denial-of-service.",
		Remediation: "Always set an explicit timeout: socket.setdefaulttimeout(30)",
	},
	{
		ID: "PY025", Severity: SevHigh, Category: CatInjection,
		Pattern:     regexp.MustCompile(`(?i)\bxmlrpc\.|xml\.etree|lxml\.etree`),
		Title:       "XML parsing — potential XXE",
		Detail:      "XML parsers may be vulnerable to XML External Entity (XXE) injection if not configured to disable external entities.",
		Remediation: "Use defusedxml library or explicitly disable external entity processing on your parser.",
	},
	{
		ID: "PY026", Severity: SevMedium, Category: CatDangerous,
		Pattern:     regexp.MustCompile(`(?i)\bopen\s*\([^)]*,\s*["']w["']\)`),
		Title:       "File opened for writing without path validation",
		Detail:      "Writing to user-supplied file paths may overwrite system or sensitive files (path traversal).",
		Remediation: "Canonicalise and validate the path with os.path.realpath() and ensure it stays within an allowed base directory.",
	},
	{
		ID: "PY027", Severity: SevHigh, Category: CatDangerous,
		Pattern:     regexp.MustCompile(`(?i)\b(zipfile\.ZipFile|tarfile\.open)\s*\(`),
		Title:       "Archive extraction — potential path traversal (zip/tar slip)",
		Detail:      "Extracting archives without validating member paths allows overwriting arbitrary files (zip slip).",
		Remediation: "Validate each archive member path to ensure it does not escape the target directory.",
	},
	{
		ID: "PY028", Severity: SevLow, Category: CatMiscConfig,
		Pattern:     regexp.MustCompile(`(?i)#\s*nosec|#\s*noqa|#\s*type:\s*ignore`),
		Title:       "Security/lint suppression comment",
		Detail:      "Suppression comments may hide real security issues from scanners.",
		Remediation: "Review each suppression to confirm it is intentional and documented.",
	},
}

// Secret / credential detection rules (multi-file)
var secretRules = []RegexRule{
	{
		ID: "SEC001", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']`),
		Title:       "Hardcoded password",
		Detail:      "A plaintext password appears to be hardcoded in source.",
		Remediation: "Use environment variables or a secrets manager (Vault, AWS Secrets Manager, etc.).",
	},
	{
		ID: "SEC002", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)(secret|secret_key|secretkey)\s*[:=]\s*["'][^"']{8,}["']`),
		Title:       "Hardcoded secret key",
		Detail:      "A secret key value appears to be hardcoded.",
		Remediation: "Store secrets outside the codebase and inject them at runtime.",
	},
	{
		ID: "SEC003", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']`),
		Title:       "Hardcoded API key",
		Detail:      "An API key appears hardcoded in source.",
		Remediation: "Inject API keys via environment variables or a secrets manager.",
	},
	{
		ID: "SEC004", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)(access_token|auth_token|bearer)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{20,}["']`),
		Title:       "Hardcoded access/auth token",
		Detail:      "An authentication token appears hardcoded in source.",
		Remediation: "Rotate the token immediately and store it in a secrets manager.",
	},
	{
		ID: "SEC005", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(AKIA|ASIA|AROA)[A-Z0-9]{16}`),
		Title:       "AWS Access Key ID",
		Detail:      "An AWS Access Key ID has been detected in source.",
		Remediation: "Revoke the key immediately via the AWS IAM console and rotate all credentials.",
	},
	{
		ID: "SEC006", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?`),
		Title:       "AWS Secret Access Key",
		Detail:      "An AWS Secret Access Key has been detected in source.",
		Remediation: "Revoke the key immediately and rotate all credentials.",
	},
	{
		ID: "SEC007", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}`),
		Title:       "GitHub Personal Access Token",
		Detail:      "A GitHub PAT has been detected in source.",
		Remediation: "Revoke the token at github.com/settings/tokens and rotate immediately.",
	},
	{
		ID: "SEC008", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)ghs_[A-Za-z0-9]{36}`),
		Title:       "GitHub Actions Secret / App Token",
		Detail:      "A GitHub Actions token has been detected. These are short-lived but should never be logged.",
		Remediation: "Ensure tokens are not printed or stored in artifacts.",
	},
	{
		ID: "SEC009", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)sk-[A-Za-z0-9]{48}`),
		Title:       "OpenAI API Key",
		Detail:      "An OpenAI API key has been detected in source.",
		Remediation: "Revoke at platform.openai.com/account/api-keys and rotate immediately.",
	},
	{
		ID: "SEC010", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)AIza[A-Za-z0-9_\-]{35}`),
		Title:       "Google API Key",
		Detail:      "A Google API key has been detected in source.",
		Remediation: "Restrict/revoke the key in Google Cloud Console.",
	},
	{
		ID: "SEC011", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)xox[bpoa]-[A-Za-z0-9\-]{10,}`),
		Title:       "Slack Token",
		Detail:      "A Slack API token has been detected.",
		Remediation: "Revoke at api.slack.com/apps and rotate.",
	},
	{
		ID: "SEC012", Severity: SevHigh, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		Title:       "Private key in source",
		Detail:      "A PEM-encoded private key has been found in source.",
		Remediation: "Remove the key from the repository immediately. Rotate the key pair.",
	},
	{
		ID: "SEC013", Severity: SevHigh, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)(jdbc|mongodb|postgresql|mysql|redis)://[^@\s]+:[^@\s]+@`),
		Title:       "Database connection string with credentials",
		Detail:      "A database URL containing inline credentials has been detected.",
		Remediation: "Move credentials to environment variables or a secrets manager.",
	},
	{
		ID: "SEC014", Severity: SevHigh, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)(smtp|imap|pop3)://[^@\s]+:[^@\s]+@`),
		Title:       "Email server credentials in URL",
		Detail:      "SMTP/IMAP/POP3 credentials found inline in a URL.",
		Remediation: "Use environment variables or a credential store for mail server credentials.",
	},
	{
		ID: "SEC015", Severity: SevMedium, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)(stripe_secret|stripe_key)\s*[:=]\s*["']sk_live_[A-Za-z0-9]{24,}["']`),
		Title:       "Stripe live secret key",
		Detail:      "A Stripe live secret key has been found.",
		Remediation: "Revoke at dashboard.stripe.com/apikeys and rotate.",
	},
	{
		ID: "SEC016", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)(twilio_auth_token|twilio_token)\s*[:=]\s*["'][a-f0-9]{32}["']`),
		Title:       "Twilio Auth Token",
		Detail:      "A Twilio authentication token has been detected.",
		Remediation: "Rotate at console.twilio.com and move to environment variables.",
	},
	{
		ID: "SEC017", Severity: SevMedium, Category: CatHardcoded,
		Pattern:     regexp.MustCompile(`(?i)(host|hostname|server)\s*[:=]\s*["'](\d{1,3}\.){3}\d{1,3}["']`),
		Title:       "Hardcoded IP address",
		Detail:      "An IP address appears hardcoded. This may expose internal infrastructure.",
		Remediation: "Use environment variables or service discovery for host addresses.",
	},
	{
		ID: "SEC018", Severity: SevHigh, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)anthropic_api_key\s*[:=]\s*["']sk-ant-[A-Za-z0-9_\-]{80,}["']`),
		Title:       "Anthropic API Key",
		Detail:      "An Anthropic API key has been detected in source.",
		Remediation: "Revoke at console.anthropic.com and rotate immediately.",
	},
}

// GitHub Actions / CI workflow specific rules
var ciRules = []RegexRule{
	{
		ID: "CI001", Severity: SevCritical, Category: CatSupplyChain,
		Pattern:     regexp.MustCompile(`uses:\s+[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+@(main|master|HEAD|latest)`),
		Title:       "GitHub Action pinned to mutable ref",
		Detail:      "Referencing an action by branch or HEAD instead of a commit SHA allows a compromised upstream to inject malicious code.",
		Remediation: "Pin actions to a full commit SHA: uses: actions/checkout@abc1234...",
	},
	{
		ID: "CI002", Severity: SevHigh, Category: CatInjection,
		Pattern:     regexp.MustCompile(`\$\{\{\s*github\.(event\.(pull_request\.(title|body|head\.ref)|issue\.(title|body)|comment\.body)|head_ref)\s*\}\}`),
		Title:       "Untrusted GitHub context used in workflow",
		Detail:      "Using user-controlled GitHub context values (PR title/body, issue body, head_ref) directly in run: steps enables script injection.",
		Remediation: "Assign the value to an intermediate environment variable and reference $ENV_VAR in the run step.",
	},
	{
		ID: "CI003", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)(password|token|secret|key)\s*:\s*["']?[A-Za-z0-9_\-\.]{8,}["']?`),
		Title:       "Possible hardcoded credential in workflow",
		Detail:      "A credential value may be hardcoded in a workflow file rather than referenced from secrets.",
		Remediation: "Replace with ${{ secrets.YOUR_SECRET_NAME }}",
	},
	{
		ID: "CI004", Severity: SevHigh, Category: CatMiscConfig,
		Pattern:     regexp.MustCompile(`pull_request_target:`),
		Title:       "pull_request_target trigger in workflow",
		Detail:      "pull_request_target runs with write permissions and access to secrets, even for forks. Combining with checkout of the PR branch can lead to pwn-request attacks.",
		Remediation: "Avoid checking out PR code in pull_request_target workflows. Use pull_request instead where possible.",
	},
	{
		ID: "CI005", Severity: SevMedium, Category: CatMiscConfig,
		Pattern:     regexp.MustCompile(`(?i)permissions:\s*write-all|permissions:\s*\{\s*\}`),
		Title:       "Overly broad workflow permissions",
		Detail:      "write-all or empty permissions block grants all permissions to the workflow token.",
		Remediation: "Follow least-privilege: specify only the permissions your workflow needs.",
	},
	{
		ID: "CI006", Severity: SevHigh, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)echo\s+\$\{\{\s*secrets\.[A-Z_]+\s*\}\}`),
		Title:       "Workflow secret printed to log",
		Detail:      "Echoing secrets to workflow logs exposes them in GitHub Actions log output.",
		Remediation: "Never print secrets. Use ::add-mask:: if a value must be used as a step output.",
	},
	{
		ID: "CI007", Severity: SevMedium, Category: CatSupplyChain,
		Pattern:     regexp.MustCompile(`(?i)(pip install|npm install|yarn add|gem install)\s+[^-\s]`),
		Title:       "Package installation without pinned version",
		Detail:      "Installing packages without pinned versions in CI can pull malicious updates.",
		Remediation: "Pin all package versions and verify checksums. Use a lock file.",
	},
	{
		ID: "CI008", Severity: SevHigh, Category: CatInjection,
		Pattern:     regexp.MustCompile(`run:\s*\|?\s*\n.*curl\s.*\|\s*(bash|sh|python)`),
		Title:       "Curl-pipe-shell pattern in CI",
		Detail:      "Piping curl output directly to a shell is a supply chain risk and can execute arbitrary remote code.",
		Remediation: "Download the script, verify its checksum, then execute it explicitly.",
	},
}

// Database file rules
var dbRules = []RegexRule{
	{
		ID: "DB001", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)INSERT INTO\s+\w+.*VALUES\s*\(.*['"][^'"]{6,}['"]`),
		Title:       "Credential-like data in SQL INSERT",
		Detail:      "SQL INSERT statements in committed files may contain real passwords or sensitive data.",
		Remediation: "Use seed scripts with placeholder/test data only. Never commit production data.",
	},
	{
		ID: "DB002", Severity: SevHigh, Category: CatMiscConfig,
		Pattern:     regexp.MustCompile(`(?i)GRANT\s+ALL\s+PRIVILEGES\s+ON\s+\*\.\*`),
		Title:       "GRANT ALL PRIVILEGES on all databases",
		Detail:      "Granting all privileges on *.* creates a superuser account that bypasses all access controls.",
		Remediation: "Follow least privilege: grant only the specific permissions required on specific databases.",
	},
	{
		ID: "DB003", Severity: SevHigh, Category: CatMiscConfig,
		Pattern:     regexp.MustCompile(`(?i)IDENTIFIED BY\s+['"][^'"]+['"]`),
		Title:       "Password in SQL IDENTIFIED BY clause",
		Detail:      "Plaintext password found in an SQL user creation or alteration statement.",
		Remediation: "Use strong, randomly generated passwords and store them in a secrets manager.",
	},
	{
		ID: "DB004", Severity: SevMedium, Category: CatMiscConfig,
		Pattern:     regexp.MustCompile(`(?i)bind_address\s*=\s*0\.0\.0\.0|listen_addresses\s*=\s*['"]\*['"]`),
		Title:       "Database listening on all interfaces",
		Detail:      "Binding the database to 0.0.0.0 or * exposes it on all network interfaces.",
		Remediation: "Bind to localhost (127.0.0.1) or a specific private interface and use a firewall.",
	},
	{
		ID: "DB005", Severity: SevMedium, Category: CatMiscConfig,
		Pattern:     regexp.MustCompile(`(?i)ssl\s*=\s*(off|0|false|no)|ssl_mode\s*=\s*disable`),
		Title:       "Database TLS/SSL disabled",
		Detail:      "SSL/TLS is disabled for database connections, exposing data in transit.",
		Remediation: "Enable SSL/TLS for all database connections.",
	},
}

// Generic config / env file rules
var configRules = []RegexRule{
	{
		ID: "CFG001", Severity: SevCritical, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)^(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*=\s*.+`),
		Title:       "AWS credentials in env/config file",
		Detail:      "AWS credentials found in a config or .env file that may be committed to source control.",
		Remediation: "Remove from the file, add to .gitignore, and use IAM roles or environment injection.",
	},
	{
		ID: "CFG002", Severity: SevHigh, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)^(DATABASE_URL|DB_PASSWORD|DB_PASS)\s*=\s*.+`),
		Title:       "Database credentials in env file",
		Detail:      "Database credentials found in a config or .env file.",
		Remediation: "Use environment variables injected at deployment and ensure .env is in .gitignore.",
	},
	{
		ID: "CFG003", Severity: SevHigh, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)^(SECRET_KEY|DJANGO_SECRET_KEY|FLASK_SECRET_KEY|APP_KEY)\s*=\s*.+`),
		Title:       "Application secret key in env file",
		Detail:      "Application secret key found in a config or .env file.",
		Remediation: "Generate a new key and inject it as a runtime environment variable.",
	},
	{
		ID: "CFG004", Severity: SevMedium, Category: CatMiscConfig,
		Pattern:     regexp.MustCompile(`(?i)^DEBUG\s*=\s*(true|1|yes|on)\s*$`),
		Title:       "Debug mode enabled in config",
		Detail:      "DEBUG=true in a production config can expose stack traces, internal state, and disable security controls.",
		Remediation: "Ensure DEBUG is false in production environments.",
	},
	{
		ID: "CFG005", Severity: SevHigh, Category: CatSecret,
		Pattern:     regexp.MustCompile(`(?i)^(PRIVATE_KEY|RSA_PRIVATE_KEY|SSL_KEY)\s*=\s*.+`),
		Title:       "Private key reference in env file",
		Detail:      "A private key value or path is stored in a config file.",
		Remediation: "Use a secrets manager or hardware security module for private key storage.",
	},
}


// ─────────────────────────────────────────────────────────────────────────────
// Python AST-level checks (using go/ast analogy via text heuristics + regex)
// For real AST we use Go's parser on a pseudo-representation; for Python we use
// line-by-line heuristic analysis which covers most real-world patterns.
// ─────────────────────────────────────────────────────────────────────────────

type ASTChecker struct{}

func (a *ASTChecker) checkPythonFile(path string, lines []string) []Finding {
	var findings []Finding

	// Track function definitions and their dangerous patterns
	type funcContext struct {
		name      string
		startLine int
		hasReturn bool
		hasAssert bool
	}

	var currentFunc *funcContext
	_ = currentFunc

	for i, line := range lines {
		stripped := strings.TrimSpace(line)
		lineNo := i + 1

		// Detect assert used for security checks (stripped in optimised Python)
		if strings.HasPrefix(stripped, "assert ") && strings.Contains(strings.ToLower(stripped), "auth") {
			findings = append(findings, Finding{
				File: path, Line: lineNo, Severity: SevHigh,
				Category: CatDangerous, RuleID: "PY_AST001",
				Title:       "assert used for authentication/authorization check",
				Detail:      "Python assertions can be disabled with -O flag, making this check a no-op in optimised mode.",
				Remediation: "Replace assert with an explicit if/raise pattern.",
				Snippet:     truncate(stripped, 120),
			})
		}

		// Detect __all__ manipulation that could expose internals
		if strings.Contains(stripped, "__all__") && strings.Contains(stripped, "append") {
			findings = append(findings, Finding{
				File: path, Line: lineNo, Severity: SevLow,
				Category: CatInfoDisclose, RuleID: "PY_AST002",
				Title:       "Dynamic modification of __all__",
				Detail:      "Dynamically appending to __all__ can unintentionally expose private symbols.",
				Remediation: "Define __all__ statically as a list literal.",
				Snippet:     truncate(stripped, 120),
			})
		}

		// Detect raw SQL string concatenation patterns
		if regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.+\+\s*`).MatchString(stripped) {
			findings = append(findings, Finding{
				File: path, Line: lineNo, Severity: SevHigh,
				Category: CatInjection, RuleID: "PY_AST003",
				Title:       "SQL string concatenation",
				Detail:      "SQL built by string concatenation is vulnerable to injection.",
				Remediation: "Use parameterised queries.",
				Snippet:     truncate(stripped, 120),
			})
		}

		// Detect use of input() in non-interactive contexts (potential injection surface)
		if regexp.MustCompile(`\binput\s*\(`).MatchString(stripped) && !strings.HasPrefix(stripped, "#") {
			findings = append(findings, Finding{
				File: path, Line: lineNo, Severity: SevLow,
				Category: CatInjection, RuleID: "PY_AST004",
				Title:       "Use of input() — untrusted data entry point",
				Detail:      "input() reads raw user input which may be passed to dangerous functions.",
				Remediation: "Validate and sanitise all input() values before use.",
				Snippet:     truncate(stripped, 120),
			})
		}

		// Detect string format methods used in SQL/shell contexts
		if regexp.MustCompile(`(?i)(execute|system|popen)\s*\(.*\.format\s*\(`).MatchString(stripped) {
			findings = append(findings, Finding{
				File: path, Line: lineNo, Severity: SevHigh,
				Category: CatInjection, RuleID: "PY_AST005",
				Title:       "str.format() used in command/query execution",
				Detail:      "String formatting in execute/system calls creates injection vulnerabilities.",
				Remediation: "Use parameterised calls instead of string formatting.",
				Snippet:     truncate(stripped, 120),
			})
		}

		// Detect open redirect patterns in web frameworks
		if regexp.MustCompile(`(?i)(redirect|HttpResponseRedirect|redirect_to)\s*\(\s*request\.(GET|POST|args|form)`).MatchString(stripped) {
			findings = append(findings, Finding{
				File: path, Line: lineNo, Severity: SevMedium,
				Category: CatInjection, RuleID: "PY_AST006",
				Title:       "Potential open redirect",
				Detail:      "Redirecting to a URL taken directly from request parameters enables open redirect attacks.",
				Remediation: "Validate redirect URLs against an allowlist of permitted destinations.",
				Snippet:     truncate(stripped, 120),
			})
		}
	}

	return findings
}

// checkGoFile runs basic security checks on Go source files using go/parser
func checkGoFile(path string, src []byte) []Finding {
	var findings []Finding

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			pos := fset.Position(node.Pos())
			pkgName := pkg.Name
			fnName := sel.Sel.Name

			// exec.Command with string concatenation
			if pkgName == "exec" && fnName == "Command" {
				findings = append(findings, Finding{
					File: path, Line: pos.Line, Severity: SevMedium,
					Category: CatInjection, RuleID: "GO001",
					Title:       "exec.Command call",
					Detail:      "Ensure arguments to exec.Command are not constructed from user input.",
					Remediation: "Validate and sanitise all arguments. Avoid shell=true equivalents.",
				})
			}

			// sql.Query / sql.Exec with potential injection
			if (pkgName == "db" || pkgName == "tx") && (fnName == "Query" || fnName == "Exec" || fnName == "QueryRow") {
				findings = append(findings, Finding{
					File: path, Line: pos.Line, Severity: SevMedium,
					Category: CatInjection, RuleID: "GO002",
					Title:       "Direct SQL query call — review for injection",
					Detail:      "Ensure queries use placeholders ($1, ?) and not string concatenation.",
					Remediation: "Use db.Query(\"SELECT ... WHERE id = $1\", id) not fmt.Sprintf.",
				})
			}

			// math/rand usage
			if pkgName == "rand" && (fnName == "Int" || fnName == "Intn" || fnName == "Float64" || fnName == "Read") {
				findings = append(findings, Finding{
					File: path, Line: pos.Line, Severity: SevMedium,
					Category: CatCrypto, RuleID: "GO003",
					Title:       "math/rand usage — not cryptographically secure",
					Detail:      "math/rand is deterministic and not suitable for security-sensitive operations.",
					Remediation: "Use crypto/rand for cryptographic purposes.",
				})
			}

			// tls.Config with InsecureSkipVerify
			if pkgName == "tls" && fnName == "Config" {
				findings = append(findings, Finding{
					File: path, Line: pos.Line, Severity: SevHigh,
					Category: CatDangerous, RuleID: "GO004",
					Title:       "tls.Config instantiation — check InsecureSkipVerify",
					Detail:      "Review whether InsecureSkipVerify is set to true, which disables certificate validation.",
					Remediation: "Never set InsecureSkipVerify: true in production code.",
				})
			}
		}
		return true
	})

	return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// File router — decide which rules apply to each file
// ─────────────────────────────────────────────────────────────────────────────

type FileType int

const (
	FTPython FileType = iota
	FTGo
	FTWorkflow  // .github/workflows/*.yml
	FTDatabase  // .sql, .db schema files
	FTConfig    // .env, *.cfg, *.ini, *.toml
	FTMarkdown  // README.md, CLAUDE.md, docs
	FTGeneric
)

func classifyFile(path string) FileType {
	lower := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))
	dirParts := strings.ToLower(filepath.ToSlash(path))

	if ext == ".py" {
		return FTPython
	}
	if ext == ".go" {
		return FTGo
	}
	if (ext == ".yml" || ext == ".yaml") && strings.Contains(dirParts, ".github/workflows") {
		return FTWorkflow
	}
	if ext == ".sql" || lower == "schema.sql" || lower == "dump.sql" || lower == "seed.sql" ||
		strings.HasSuffix(lower, ".sqlite") || strings.HasSuffix(lower, ".db.sql") {
		return FTDatabase
	}
	if ext == ".env" || lower == ".env" || strings.HasPrefix(lower, ".env.") ||
		ext == ".cfg" || ext == ".ini" || ext == ".conf" || ext == ".toml" || lower == "settings.py" {
		return FTConfig
	}
	if ext == ".md" || ext == ".mdx" || lower == "claude.md" || lower == "readme.md" {
		return FTMarkdown
	}
	return FTGeneric
}

// shouldSkipPath returns true for paths that should never be scanned
func shouldSkipPath(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	skips := []string{
		"/.git/", "/node_modules/", "/__pycache__/", "/.venv/", "/venv/",
		"/dist/", "/build/", "/.mypy_cache/", "/.tox/", "/vendor/",
		"/.pytest_cache/", "/site-packages/",
	}
	for _, s := range skips {
		if strings.Contains(lower, s) {
			return true
		}
	}
	// Skip binary extensions
	binaryExts := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
		".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".tgz", ".exe",
		".dll", ".so", ".dylib", ".class", ".jar", ".pyc",
	}
	ext := strings.ToLower(filepath.Ext(path))
	for _, e := range binaryExts {
		if ext == e {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Scanner core
// ─────────────────────────────────────────────────────────────────────────────

type Scanner struct {
	rootPath    string
	minSeverity Severity
	workers     int
	astChecker  *ASTChecker
}

func NewScanner(root string, minSev Severity, workers int) *Scanner {
	return &Scanner{
		rootPath:    root,
		minSeverity: minSev,
		workers:     workers,
		astChecker:  &ASTChecker{},
	}
}

func (s *Scanner) Scan() ScanResult {
	result := ScanResult{
		StartedAt: time.Now(),
		RootPath:  s.rootPath,
		Stats:     map[string]int{},
	}

	// Collect files
	var files []string
	_ = filepath.WalkDir(s.rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if shouldSkipPath(path) {
			return nil
		}
		files = append(files, path)
		return nil
	})

	result.FilesTotal = len(files)

	// Fan-out to workers
	type work struct {
		path string
	}
	jobs := make(chan work, len(files))
	results := make(chan []Finding, len(files))

	var wg sync.WaitGroup
	numWorkers := s.workers
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				findings := s.scanFile(j.path)
				results <- findings
			}
		}()
	}

	for _, f := range files {
		jobs <- work{f}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var allFindings []Finding
	scanned := 0
	for ff := range results {
		if len(ff) > 0 {
			scanned++
		}
		allFindings = append(allFindings, ff...)
	}

	// Filter by severity
	var filtered []Finding
	for _, f := range allFindings {
		if f.Severity >= s.minSeverity {
			filtered = append(filtered, f)
		}
	}

	// Sort by severity desc, then file+line
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Severity != filtered[j].Severity {
			return filtered[i].Severity > filtered[j].Severity
		}
		if filtered[i].File != filtered[j].File {
			return filtered[i].File < filtered[j].File
		}
		return filtered[i].Line < filtered[j].Line
	})

	// Stats
	for _, f := range filtered {
		result.Stats[f.Severity.String()]++
		result.Stats["cat_"+string(f.Category)]++
	}

	result.Findings = filtered
	result.FilesScanned = result.FilesTotal
	result.FinishedAt = time.Now()
	return result
}

func (s *Scanner) scanFile(path string) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Sanitise path for display
	relPath := path
	if rel, err := filepath.Rel(s.rootPath, path); err == nil {
		relPath = rel
	}

	ft := classifyFile(path)
	var findings []Finding

	lines := strings.Split(string(data), "\n")

	// Apply rule sets based on file type
	switch ft {
	case FTPython:
		findings = append(findings, applyRegexRules(relPath, lines, pythonRules)...)
		findings = append(findings, applyRegexRules(relPath, lines, secretRules)...)
		findings = append(findings, s.astChecker.checkPythonFile(relPath, lines)...)

	case FTGo:
		findings = append(findings, checkGoFile(relPath, data)...)
		findings = append(findings, applyRegexRules(relPath, lines, secretRules)...)

	case FTWorkflow:
		findings = append(findings, applyRegexRules(relPath, lines, ciRules)...)
		findings = append(findings, applyRegexRules(relPath, lines, secretRules)...)

	case FTDatabase:
		findings = append(findings, applyRegexRules(relPath, lines, dbRules)...)
		findings = append(findings, applyRegexRules(relPath, lines, secretRules)...)

	case FTConfig:
		findings = append(findings, applyRegexRules(relPath, lines, configRules)...)
		findings = append(findings, applyRegexRules(relPath, lines, secretRules)...)

	case FTMarkdown:
		findings = append(findings, applyRegexRules(relPath, lines, secretRules)...)

	default:
		// Generic: secrets only
		findings = append(findings, applyRegexRules(relPath, lines, secretRules)...)
	}

	return findings
}

func applyRegexRules(path string, lines []string, rules []RegexRule) []Finding {
	var findings []Finding
	for _, rule := range rules {
		findings = append(findings, applyRule(path, lines, rule)...)
	}
	return findings
}

func applyRule(path string, lines []string, rule RegexRule) []Finding {
	var findings []Finding
	for i, line := range lines {
		// Optionally skip lines that are comments
		if rule.SkipComments {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") ||
				strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
				continue
			}
		}
		if rule.Pattern.MatchString(line) {
			// Find column of match
			loc := rule.Pattern.FindStringIndex(line)
			col := 0
			if loc != nil {
				col = loc[0] + 1
			}
			findings = append(findings, Finding{
				File:        path,
				Line:        i + 1,
				Column:      col,
				Severity:    rule.Severity,
				Category:    rule.Category,
				RuleID:      rule.ID,
				Title:       rule.Title,
				Detail:      rule.Detail,
				Snippet:     truncate(strings.TrimSpace(line), 120),
				Remediation: rule.Remediation,
			})
		}
	}
	return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// Output formatters
// ─────────────────────────────────────────────────────────────────────────────

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorYellow  = "\033[33m"
	colorCyan    = "\033[36m"
	colorMagenta = "\033[35m"
	colorGray    = "\033[90m"
	colorBold    = "\033[1m"
	colorGreen   = "\033[32m"
)

func sevColor(s Severity, noColor bool) string {
	if noColor {
		return ""
	}
	switch s {
	case SevCritical:
		return colorRed + colorBold
	case SevHigh:
		return colorRed
	case SevMedium:
		return colorYellow
	case SevLow:
		return colorCyan
	}
	return ""
}

func printText(result ScanResult, noColor bool, w *bufio.Writer) {
	reset := colorReset
	bold := colorBold
	gray := colorGray
	green := colorGreen
	if noColor {
		reset, bold, gray, green = "", "", "", ""
	}

	_, _ = fmt.Fprintf(w, "\n%s╔══════════════════════════════════════════════════════╗%s\n", bold, reset)
	_, _ = fmt.Fprintf(w, "%s║         Policy Security Scanner — Report             ║%s\n", bold, reset)
	_, _ = fmt.Fprintf(w, "%s╚══════════════════════════════════════════════════════╝%s\n\n", bold, reset)

	_, _ = fmt.Fprintf(w, "  %sRoot:%s     %s\n", bold, reset, result.RootPath)
	_, _ = fmt.Fprintf(w, "  %sScanned:%s  %d files\n", bold, reset, result.FilesScanned)
	_, _ = fmt.Fprintf(w, "  %sDuration:%s %s\n\n", bold, reset, result.FinishedAt.Sub(result.StartedAt).Round(time.Millisecond))

	if len(result.Findings) == 0 {
		_, _ = fmt.Fprintf(w, "  %s✓ No findings above minimum severity threshold.%s\n\n", green, reset)
		return
	}

	_, _ = fmt.Fprintf(w, "  %sSummary:%s\n", bold, reset)
	for _, sev := range []Severity{SevCritical, SevHigh, SevMedium, SevLow} {
		count := result.Stats[sev.String()]
		if count > 0 {
			col := sevColor(sev, noColor)
			_, _ = fmt.Fprintf(w, "    %s%-10s%s %d\n", col, sev.String(), reset, count)
		}
	}
	_, _ = fmt.Fprintln(w)

	// Group findings by file
	byFile := map[string][]Finding{}
	var fileOrder []string
	seen := map[string]bool{}
	for _, f := range result.Findings {
		if !seen[f.File] {
			fileOrder = append(fileOrder, f.File)
			seen[f.File] = true
		}
		byFile[f.File] = append(byFile[f.File], f)
	}

	for _, file := range fileOrder {
		ff := byFile[file]
		_, _ = fmt.Fprintf(w, "%s┌─ %s%s\n", bold, file, reset)
		for _, f := range ff {
			col := sevColor(f.Severity, noColor)
			_, _ = fmt.Fprintf(w, "│  %s[%s]%s %s[%s]%s %s — line %d\n",
				col, f.Severity, reset,
				gray, f.RuleID, reset,
				f.Title, f.Line)
			_, _ = fmt.Fprintf(w, "│     %sDetail:%s %s\n", bold, reset, f.Detail)
			if f.Snippet != "" {
				_, _ = fmt.Fprintf(w, "│     %sSnippet:%s %s%s%s\n", bold, reset, gray, f.Snippet, reset)
			}
			if f.Remediation != "" {
				_, _ = fmt.Fprintf(w, "│     %sFix:%s    %s\n", bold, reset, f.Remediation)
			}
			_, _ = fmt.Fprintln(w, "│")
		}
		_, _ = fmt.Fprintln(w, "└")
	}
}

func printJSON(result ScanResult, w *bufio.Writer) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	var (
		flagPath     = flag.String("path", ".", "Root path to scan")
		flagJSON     = flag.Bool("json", false, "Output results as JSON")
		flagSeverity = flag.String("severity", "low", "Minimum severity: low|medium|high|critical")
		flagNoColor  = flag.Bool("no-color", false, "Disable ANSI colour output")
		flagWorkers  = flag.Int("workers", 4, "Number of parallel scan workers")
		flagOut      = flag.String("out", "", "Write report to this file instead of stdout")
	)
	flag.Parse()

	// Allow positional argument as path
	if flag.NArg() > 0 {
		*flagPath = flag.Arg(0)
	}

	abs, err := filepath.Abs(*flagPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving path: %v\n", err)
		os.Exit(1)
	}

	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "path does not exist or is not a directory: %s\n", abs)
		os.Exit(1)
	}

	minSev := parseSeverity(*flagSeverity)
	scanner := NewScanner(abs, minSev, *flagWorkers)
	result := scanner.Scan()

	// Choose output destination
	var outFile *os.File
	if *flagOut != "" {
		outFile, err = os.Create(*flagOut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot create output file: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
	} else {
		outFile = os.Stdout
	}

	w := bufio.NewWriter(outFile)
	defer w.Flush()

	if *flagJSON {
		printJSON(result, w)
	} else {
		noColor := *flagNoColor || *flagOut != ""
		printText(result, noColor, w)
	}

	// Exit code: 0 = clean, 1 = findings present, 2 = critical findings
	if result.Stats["CRITICAL"] > 0 {
		os.Exit(2)
	}
	if len(result.Findings) > 0 {
		os.Exit(1)
	}
}