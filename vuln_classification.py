# ══════════════════════════════════════════════════════════════════════════════
# Vulnerability-type consolidation (186 HackerOne types → 34 semantic categories)
# ══════════════════════════════════════════════════════════════════════════════
master_map = {
    # XSS
    "Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)": "Cross-site Scripting (XSS) - Generic",
    "Cross-Site Scripting (XSS)": "Cross-site Scripting (XSS) - Generic",
    "Reflected XSS": "Cross-site Scripting (XSS) - Reflected",
    # SSRF
    "Server Side Request Forgery": "Server-Side Request Forgery (SSRF)",
    # Path Traversal
    "Path Traversal: '.../...//'": "Path Traversal",
    "Path Traversal: 'dir\\..\\..\\filename'": "Path Traversal",
    "Relative Path Traversal": "Path Traversal",
    # File Inclusion
    "PHP Local File Inclusion": "File Inclusion",
    "Remote File Inclusion": "File Inclusion",
    "File Content Injection": "File Inclusion",
    "External Control of File Name or Path": "File Inclusion",
    # XXE
    "XML Injection": "XML External Entities (XXE)",
    "XML Entity Expansion": "XML External Entities (XXE)",
    # Improper Authentication
    "Improper Authentication - Generic": "Improper Authentication",
    "Missing Authentication for Critical Function": "Improper Authentication",
    "Missing Critical Step in Authentication": "Improper Authentication",
    "Improper Restriction of Authentication Attempts": "Improper Authentication",
    "Authentication Bypass": "Improper Authentication",
    "Authentication Bypass by Primary Weakness": "Improper Authentication",
    "Authentication Bypass Using an Alternate Path or Channel": "Improper Authentication",
    "Authentication Bypass by Capture-replay": "Improper Authentication",
    "Brute Force": "Improper Authentication",
    "Unverified Password Change": "Improper Authentication",
    # Improper Authorization
    "Improper Access Control - Generic": "Improper Authorization",
    "Incorrect Authorization": "Improper Authorization",
    "Missing Authorization": "Improper Authorization",
    "Forced Browsing": "Improper Authorization",
    "Client-Side Enforcement of Server-Side Security": "Improper Authorization",
    "Incorrect Permission Assignment for Critical Resource": "Improper Authorization",
    "Improper Handling of Insufficient Permissions or Privileges": "Improper Authorization",
    "Privacy Violation": "Improper Authorization",
    "Improper Preservation of Permissions": "Improper Authorization",
    "Incorrect Default Permissions": "Improper Authorization",
    "Access Control Check Implemented After Asset is Accessed": "Improper Authorization",
    "LLM09:2025 Misinformation": "Improper Authorization",
    # Privilege Escalation
    "Execution with Unnecessary Privileges": "Privilege Escalation",
    "Improper Privilege Management": "Privilege Escalation",
    "Incorrect Privilege Assignment": "Privilege Escalation",
    # Credential & Session Management
    "Plaintext Storage of a Password": "Credential & Session Management",
    "Use of Hard-coded Credentials": "Credential & Session Management",
    "Use of Hard-coded Password": "Credential & Session Management",
    "Use of Default Credentials": "Credential & Session Management",
    "Weak Cryptography for Passwords": "Credential & Session Management",
    "Weak Password Recovery Mechanism for Forgotten Password": "Credential & Session Management",
    "Session Fixation": "Credential & Session Management",
    "Reusing Session IDs (aka Session Replay)": "Credential & Session Management",
    "Storing Passwords in a Recoverable Format": "Credential & Session Management",
    "Unprotected Transport of Credentials": "Credential & Session Management",
    "Insufficient Session Expiration": "Credential & Session Management",
    "Insufficiently Protected Credentials": "Credential & Session Management",
    "Reliance on Cookies without Validation and Integrity Checking in a Security Decision": "Credential & Session Management",
    "Reliance on Untrusted Inputs in a Security Decision": "Credential & Session Management",
    "Password in Configuration File": "Credential & Session Management",
    "Exposure of Data Element to Wrong Session": "Credential & Session Management",
    "Weak Password Requirements": "Credential & Session Management",
    # Sensitive Data Exposure
    "Cleartext Storage of Sensitive Information": "Sensitive Data Exposure",
    "Cleartext Transmission of Sensitive Information": "Sensitive Data Exposure",
    "Cleartext Storage in a File or on Disk": "Sensitive Data Exposure",
    "Insecure Storage of Sensitive Information": "Sensitive Data Exposure",
    "Missing Encryption of Sensitive Data": "Sensitive Data Exposure",
    # Cryptographic Weakness
    "Key Exchange without Entity Authentication": "Cryptographic Weakness",
    "Reusing a Nonce, Key Pair in Encryption": "Cryptographic Weakness",
    "Use of a Broken or Risky Cryptographic Algorithm": "Cryptographic Weakness",
    "Inadequate Encryption Strength": "Cryptographic Weakness",
    "Use of Hard-coded Cryptographic Key": "Cryptographic Weakness",
    "Use of a Key Past its Expiration Date": "Cryptographic Weakness",
    "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)": "Cryptographic Weakness",
    "Use of Insufficiently Random Values": "Cryptographic Weakness",
    "Missing Required Cryptographic Step": "Cryptographic Weakness",
    "Cryptographic Issues - Generic": "Cryptographic Weakness",
    "Reversible One-Way Hash": "Cryptographic Weakness",
    # Certificate & Transport Security
    "Improper Certificate Validation": "Certificate & Transport Security",
    "Improper Validation of Certificate with Host Mismatch": "Certificate & Transport Security",
    "Improper Check for Certificate Revocation": "Certificate & Transport Security",
    "Improper Following of a Certificate's Chain of Trust": "Certificate & Transport Security",
    "Improper Verification of Cryptographic Signature": "Certificate & Transport Security",
    "Man-in-the-Middle": "Certificate & Transport Security",
    "Insufficient Verification of Data Authenticity": "Certificate & Transport Security",
    "Download of Code Without Integrity Check": "Certificate & Transport Security",
    "Improper Validation of Certificate Expiration": "Certificate & Transport Security",
    "Exploiting Incorrectly Configured SSL/TLS": "Certificate & Transport Security",
    # Information Disclosure
    "Exposure of Sensitive Information Due to Incompatible Policies": "Information Disclosure",
    "Use of Cache Containing Sensitive Information": "Information Disclosure",
    "Information Exposure Through an Error Message": "Information Disclosure",
    "Information Exposure Through Debug Information": "Information Disclosure",
    "Information Exposure Through Sent Data": "Information Disclosure",
    "File and Directory Information Exposure": "Information Disclosure",
    "Information Exposure Through Timing Discrepancy": "Information Disclosure",
    "LLM06: Sensitive Information Disclosure": "Information Disclosure",
    "Inclusion of Sensitive Information in an Include File": "Information Disclosure",
    "Improper Removal of Sensitive Information Before Storage or Transfer": "Information Disclosure",
    "Insertion of Sensitive Information into Log File": "Information Disclosure",
    # Race Condition
    "Time-of-check Time-of-use (TOCTOU) Race Condition": "Race Condition",
    "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')": "Race Condition",
    "Leveraging Race Conditions": "Race Condition",
    "Improper Synchronization": "Race Condition",
    # Misconfiguration
    "Cache Poisoning": "Misconfiguration",
    "Untrusted Search Path": "Misconfiguration",
    "Unrestricted Upload of File with Dangerous Type": "Misconfiguration",
    "Security Through Obscurity": "Misconfiguration",
    "Insufficient Logging": "Misconfiguration",
    "Insecure Temporary File": "Misconfiguration",
    "Improper Export of Android Application Components": "Misconfiguration",
    "Improper Link Resolution Before File Access ('Link Following')": "Misconfiguration",
    "Insecure Default Initialization of Resource": "Misconfiguration",
    "Uncontrolled Search Path Element": "Misconfiguration",
    "Inconsistency Between Implementation and Documented Design": "Misconfiguration",
    "Reliance on Reverse DNS Resolution for a Security-Critical Action": "Misconfiguration",
    "Use of Incorrectly-Resolved Name or Reference": "Misconfiguration",
    "File Manipulation": "Misconfiguration",
    "Leftover Debug Code (Backdoor)": "Misconfiguration",
    "Information Exposure Through Directory Listing": "Misconfiguration",
    # SQL Injection
    "Blind SQL Injection": "SQL Injection",
    "NoSQL Injection": "SQL Injection",
    # Memory Corruption
    "Buffer Over-read": "Memory Corruption", "Out-of-bounds Read": "Memory Corruption",
    "Buffer Under-read": "Memory Corruption", "Buffer Underflow": "Memory Corruption",
    "Classic Buffer Overflow": "Memory Corruption", "Integer Overflow": "Memory Corruption",
    "Integer Underflow": "Memory Corruption", "Integer Overflow to Buffer Overflow ": "Memory Corruption",
    "Array Index Underflow": "Memory Corruption", "Off-by-one Error": "Memory Corruption",
    "Wrap-around Error": "Memory Corruption", "Heap Overflow": "Memory Corruption",
    "Stack Overflow": "Memory Corruption", "Free of Memory not on the Heap": "Memory Corruption",
    "NULL Pointer Dereference": "Memory Corruption", "Improper Null Termination": "Memory Corruption",
    "Write-what-where Condition": "Memory Corruption", "Double Free": "Memory Corruption",
    "Use After Free": "Memory Corruption", "Memory Corruption - Generic": "Memory Corruption",
    "Incorrect Calculation of Buffer Size": "Memory Corruption", "Type Confusion": "Memory Corruption",
    "Integer Overflow to Buffer Overflow": "Memory Corruption",
    "Improper Resource Shutdown or Release": "Memory Corruption",
    "Missing Release of Memory after Effective Lifetime": "Memory Corruption",
    "Improper Initialization": "Memory Corruption",
    # Improper Input Validation
    "Acceptance of Extraneous Untrusted Data With Trusted Data": "Improper Input Validation",
    "Incorrect Comparison": "Business Logic Errors",
    "Improper Neutralization of Value Delimiters": "Improper Input Validation",
    "Partial String Comparison": "Improper Input Validation",
    "Improper Output Neutralization for Logs": "Improper Input Validation",
    "Improper Handling of Case Sensitivity": "Business Logic Errors",
    "Improper Handling of Unicode Encoding": "Improper Input Validation",
    "Improper Validation of Syntactic Correctness of Input": "Improper Input Validation",
    "Improper Handling of Unexpected Data Type": "Improper Input Validation",
    "Improper Neutralization of Escape, Meta, or Control Sequences": "Improper Input Validation",
    "Improper Neutralization of Whitespace": "Improper Input Validation",
    "Improper Neutralization of Formula Elements in a CSV File,": "Improper Input Validation",
    "Improper Neutralization of HTTP Headers for Scripting Syntax": "Improper Input Validation",
    "Modification of Assumed-Immutable Data (MAID)": "Improper Input Validation",
    "Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)": "Improper Input Validation",
    "Improper Handling of URL Encoding (Hex Encoding)": "Improper Input Validation",
    "Improper Neutralization of Formula Elements in a CSV File": "Improper Input Validation",
    "Externally Controlled Reference to a Resource in Another Sphere": "Improper Input Validation",
    "External Control of Critical State Data": "Improper Input Validation",
    "Misinterpretation of Input": "Improper Input Validation",
    "Encoding Error": "Improper Input Validation",
    "Resource Injection": "Improper Input Validation",
    "Use of Inherently Dangerous Function": "Improper Input Validation",
    "Improper Check or Handling of Exceptional Conditions": "Improper Input Validation",
    "Unchecked Error Condition": "Improper Input Validation",
    "Expected Behavior Violation": "Improper Input Validation",
    "Exposed Dangerous Method or Function": "Improper Input Validation",
    "Improper Handling of Exceptional Conditions": "Improper Input Validation",
    # Command Injection
    "Command Injection - Generic": "Command Injection",
    "OS Command Injection": "Command Injection",
    "LDAP Injection": "Command Injection",
    # Code Injection
    "Use of Externally-Controlled Format String": "Code Injection",
    "LLM01: Prompt Injection": "Code Injection",
    "ASI05: Unexpected Code Execution (RCE)": "Code Injection",
    # Denial of Service
    "Uncontrolled Resource Consumption": "Denial of Service",
    "Allocation of Resources Without Limits or Throttling": "Denial of Service",
    "Uncontrolled Recursion": "Denial of Service",
    "LLM04: Model Denial of Service": "Denial of Service",
    "Loop with Unreachable Exit Condition ('Infinite Loop')": "Denial of Service",
    "Improper Handling of Highly Compressed Data (Data Amplification)": "Denial of Service",
    "Reachable Assertion": "Denial of Service",
    # HTTP Request Manipulation
    "HTTP Request Smuggling": "HTTP Request Manipulation",
    "CRLF Injection": "HTTP Request Manipulation",
    "HTTP Response Splitting": "HTTP Request Manipulation",
    # Phishing / Spoofing
    "Phishing": "Phishing / Spoofing",
    "Content Spoofing": "Phishing / Spoofing",
    "User Interface (UI) Misrepresentation of Critical Information": "Phishing / Spoofing",
    "Authentication Bypass by Spoofing": "Phishing / Spoofing",
    # Supply Chain / Third-Party
    "Using Components with Known Vulnerabilities": "Supply Chain / Third-Party",
    "Inclusion of Functionality from Untrusted Control Sphere": "Supply Chain / Third-Party",
    "LLM05: Supply Chain Vulnerabilities": "Supply Chain / Third-Party",
    "Embedded Malicious Code": "Supply Chain / Third-Party",
    "Malware": "Supply Chain / Third-Party",
}

"""
Vulnerability Classification Module
Maps consolidated HackerOne vulnerability categories to:
  - CWE IDs
  - OWASP Top 10 (2025)
  - Root Causes (true root causes, not symptoms or attack patterns)
  - Preventability Score (1-5, where 5 = easiest to prevent)

OWASP Top 10:2025
  A01:2025 - Broken Access Control
  A02:2025 - Security Misconfiguration
  A03:2025 - Software Supply Chain Failures
  A04:2025 - Cryptographic Failures
  A05:2025 - Injection
  A06:2025 - Insecure Design
  A07:2025 - Authentication Failures
  A08:2025 - Software or Data Integrity Failures
  A09:2025 - Security Logging and Alerting Failures
  A10:2025 - Mishandling of Exceptional Conditions
"""


# Classification mapping
owasp_cwe_classification = {
    "Cross-site Scripting (XSS) - Generic": {
        "cwes": ["CWE-79"],
        "owasp_2025": ["A05:2025 - Injection"],
        "root_causes": [
            "Missing output encoding/escaping",
            "Missing Content-Security-Policy headers",
            "Insufficient input validation",
        ],
        "preventability": 4,
        "preventability_rationale": "Framework auto-escaping prevents it",
    },
    "Cross-site Scripting (XSS) - Reflected": {
        "cwes": ["CWE-79"],
        "owasp_2025": ["A05:2025 - Injection"],
        "root_causes": [
            "Missing output encoding/escaping on reflected input",
            "No server-side sanitization before rendering user input",
            "Missing Content-Security-Policy headers",
        ],
        "preventability": 4,
        "preventability_rationale": "Framework auto-escaping, but depends on framework choice",
    },
    "Server-Side Request Forgery (SSRF)": {
        "cwes": ["CWE-918"],
        "owasp_2025": ["A01:2025 - Broken Access Control"],
        "root_causes": [
            "No validation or allowlisting of user-supplied URLs",
            "Missing network segmentation between application and internal services",
            "Application-level outbound requests not restricted by destination",
        ],
        "preventability": 3,
        "preventability_rationale": "Requires URL allowlisting across all outbound request paths",
    },
    "Path Traversal": {
        "cwes": ["CWE-22", "CWE-23", "CWE-36"],
        "owasp_2025": ["A01:2025 - Broken Access Control"],
        "root_causes": [
            "Missing path canonicalization before file access",
            "No restriction of file system access to a safe base directory",
            "Insufficient validation of user-supplied file paths",
        ],
        "preventability": 4,
        "preventability_rationale": "Framework file-serving abstractions prevent it",
    },
    "File Inclusion": {
        "cwes": ["CWE-98", "CWE-73", "CWE-829"],
        "owasp_2025": [
            "A05:2025 - Injection",
            "A01:2025 - Broken Access Control",
        ],
        "root_causes": [
            "Dynamic file inclusion driven by user-controlled input",
            "No allowlist restricting which files can be included",
            "Insufficient input validation on file path parameters",
        ],
        "preventability": 4,
        "preventability_rationale": "Avoid dynamic includes, use allowlists -- well-known pattern",
    },
    "XML External Entities (XXE)": {
        "cwes": ["CWE-611", "CWE-776"],
        "owasp_2025": ["A02:2025 - Security Misconfiguration"],
        "root_causes": [
            "XML parser not configured to disable external entity resolution",
            "DTD processing left enabled in parser settings",
            "Use of XML libraries with insecure defaults",
        ],
        "preventability": 5,
        "preventability_rationale": "Modern parsers disable external entities by default",
    },
    "Improper Authentication": {
        "cwes": ["CWE-287", "CWE-306", "CWE-304", "CWE-305", "CWE-307", "CWE-288", "CWE-620"],
        "owasp_2025": ["A07:2025 - Authentication Failures"],
        "root_causes": [
            "Missing or weak authentication checks on critical functions",
            "No rate-limiting or account lockout on login attempts",
            "Inconsistent authentication enforcement across entry points",
            "Lack of multi-factor authentication for sensitive operations",
        ],
        "preventability": 3,
        "preventability_rationale": "Well-known patterns (MFA, rate limiting) but many entry points",
    },
    "Improper Authorization": {
        "cwes": ["CWE-284", "CWE-863", "CWE-862", "CWE-425", "CWE-732"],
        "owasp_2025": ["A01:2025 - Broken Access Control"],
        "root_causes": [
            "Missing server-side authorization checks on resources and actions",
            "Missing object-level ownership validation before granting access",
            "Reliance on client-side enforcement for access control decisions",
            "Inconsistent or poorly defined permission model",
        ],
        "preventability": 3,
        "preventability_rationale": "Authorization middleware/decorators are well-established; requires discipline",
    },
    "Privilege Escalation": {
        "cwes": ["CWE-250", "CWE-269", "CWE-266"],
        "owasp_2025": ["A01:2025 - Broken Access Control"],
        "root_causes": [
            "Processes or services running with excessive privileges",
            "Missing enforcement of the principle of least privilege",
            "Flawed role assignment or role-based access control logic",
        ],
        "preventability": 3,
        "preventability_rationale": "RBAC and least-privilege are well-known patterns; requires discipline",
    },
    "Credential & Session Management": {
        "cwes": [
            "CWE-256", "CWE-257", "CWE-798", "CWE-259", "CWE-521",
            "CWE-916", "CWE-640", "CWE-384", "CWE-613", "CWE-522",
        ],
        "owasp_2025": [
            "A07:2025 - Authentication Failures",
            "A04:2025 - Cryptographic Failures",
        ],
        "root_causes": [
            "Passwords stored in plaintext or reversible format",
            "Hard-coded or default credentials in source code or config",
            "Weak or predictable session ID generation",
            "Missing session expiration, rotation, or invalidation on logout",
        ],
        "preventability": 3,
        "preventability_rationale": "Many moving parts (storage, rotation, expiration, transport)",
    },
    "Sensitive Data Exposure": {
        "cwes": ["CWE-312", "CWE-319", "CWE-922", "CWE-311"],
        "owasp_2025": ["A04:2025 - Cryptographic Failures"],
        "root_causes": [
            "Missing encryption for data at rest or in transit",
            "Sensitive data stored in cleartext without access controls",
            "Insufficient data classification leading to unprotected sensitive fields",
        ],
        "preventability": 3,
        "preventability_rationale": "Requires upfront data classification and encryption strategy",
    },
    "Cryptographic Weakness": {
        "cwes": [
            "CWE-327", "CWE-326", "CWE-321", "CWE-324",
            "CWE-338", "CWE-330", "CWE-325", "CWE-310",
        ],
        "owasp_2025": ["A04:2025 - Cryptographic Failures"],
        "root_causes": [
            "Use of deprecated or weak cryptographic algorithms",
            "Hard-coded, expired, or improperly managed cryptographic keys",
            "Use of non-cryptographic or weak pseudo-random number generators",
            "Omission of required cryptographic steps (e.g., HMAC, salt)",
        ],
        "preventability": 3,
        "preventability_rationale": "Requires knowledge of current best practices; easy to pick wrong algorithm",
    },
    "Certificate & Transport Security": {
        "cwes": [
            "CWE-295", "CWE-297", "CWE-299", "CWE-296",
            "CWE-347", "CWE-300", "CWE-345", "CWE-494",
        ],
        "owasp_2025": [
            "A04:2025 - Cryptographic Failures",
            "A07:2025 - Authentication Failures",
        ],
        "root_causes": [
            "Missing or disabled TLS certificate validation",
            "HTTPS / HSTS not enforced across all endpoints",
            "No integrity verification of downloaded code or updates",
            "Acceptance of self-signed, expired, or mismatched certificates",
        ],
        "preventability": 4,
        "preventability_rationale": "TLS defaults and HSTS are well-established",
    },
    "Information Disclosure": {
        "cwes": [
            "CWE-200", "CWE-209", "CWE-215", "CWE-260",
            "CWE-538", "CWE-548", "CWE-532", "CWE-359", "CWE-208",
        ],
        "owasp_2025": [
            "A01:2025 - Broken Access Control",
            "A02:2025 - Security Misconfiguration",
        ],
        "root_causes": [
            "Verbose error messages exposed in production",
            "Debug endpoints or leftover debug code not removed before deployment",
            "Directory listing enabled on web server",
            "Sensitive data written to logs, caches, or responses without filtering",
        ],
        "preventability": 3,
        "preventability_rationale": "Many leak vectors (logs, errors, caches, debug endpoints); no single prevention pattern",
    },
    "Race Condition": {
        "cwes": ["CWE-362", "CWE-367"],
        "owasp_2025": ["A06:2025 - Insecure Design"],
        "root_causes": [
            "Missing atomic operations or locking around shared resources",
            "Non-atomic check-then-act sequences in security-critical logic",
            "Shared mutable state accessed without proper synchronization",
        ],
        "preventability": 2,
        "preventability_rationale": "Requires careful concurrent design; hard to test for",
    },
    "Misconfiguration": {
        "cwes": [
            "CWE-16", "CWE-434", "CWE-656", "CWE-778",
            "CWE-377", "CWE-706", "CWE-426", "CWE-59", "CWE-926",
        ],
        "owasp_2025": [
            "A02:2025 - Security Misconfiguration",
            "A09:2025 - Security Logging and Alerting Failures",
        ],
        "root_causes": [
            "Insecure default configurations not hardened before deployment",
            "No restriction on uploaded file types or content validation",
            "Insufficient logging, monitoring, or alerting configuration",
            "Missing security hardening steps in deployment pipeline",
        ],
        "preventability": 3,
        "preventability_rationale": "Requires systematic hardening across all components",
    },
    "SQL Injection": {
        "cwes": ["CWE-89"],
        "owasp_2025": ["A05:2025 - Injection"],
        "root_causes": [
            "String concatenation of user input into SQL queries",
            "Failure to use parameterized queries or prepared statements",
            "Insufficient input validation on query parameters",
        ],
        "preventability": 5,
        "preventability_rationale": "ORMs/parameterized queries are the default path",
    },
    "Memory Corruption": {
        "cwes": [
            "CWE-120", "CWE-122", "CWE-121", "CWE-125", "CWE-787",
            "CWE-190", "CWE-191", "CWE-680", "CWE-131", "CWE-193",
            "CWE-416", "CWE-415", "CWE-404", "CWE-476", "CWE-170",
            "CWE-123", "CWE-843",
        ],
        "owasp_2025": ["A06:2025 - Insecure Design"],
        "root_causes": [
            "Use of memory-unsafe languages without bounds checking",
            "Missing bounds validation on buffer operations",
            "Improper memory lifecycle management (allocation, use, release)",
            "Unchecked arithmetic on integer values used for memory sizing",
        ],
        "preventability": 4,
        "preventability_rationale": "Memory-safe languages (Rust, Go, Java) are standard tooling; choosing one over C/C++ is a straightforward decision for new projects",
    },
    "Improper Input Validation": {
        "cwes": ["CWE-20", "CWE-150", "CWE-116", "CWE-1286"],
        "owasp_2025": [
            "A05:2025 - Injection",
            "A10:2025 - Mishandling of Exceptional Conditions",
        ],
        "root_causes": [
            "Missing or incomplete input validation and sanitization",
            "Trusting client-supplied data types or encodings without verification",
            "No allowlist-based validation strategy for expected input",
        ],
        "preventability": 3,
        "preventability_rationale": "Broad category, requires validation discipline everywhere",
    },
    "Command Injection": {
        "cwes": ["CWE-77", "CWE-78", "CWE-90"],
        "owasp_2025": ["A05:2025 - Injection"],
        "root_causes": [
            "User input passed directly to system shell or command interpreter",
            "Missing input sanitization or allowlisting on command arguments",
            "Use of shell execution functions instead of safe library APIs",
        ],
        "preventability": 4,
        "preventability_rationale": "Use library APIs instead of shell execution",
    },
    "Code Injection": {
        "cwes": ["CWE-94", "CWE-134"],
        "owasp_2025": ["A05:2025 - Injection"],
        "root_causes": [
            "Dynamic code evaluation with user-controlled input (eval, exec)",
            "User-controlled values passed into format string functions",
            "Missing sandboxing or isolation for untrusted code execution",
        ],
        "preventability": 4,
        "preventability_rationale": "Avoid eval/exec, well-known pattern",
    },
    "Denial of Service": {
        "cwes": ["CWE-400", "CWE-770", "CWE-674", "CWE-835"],
        "owasp_2025": [
            "A06:2025 - Insecure Design",
            "A10:2025 - Mishandling of Exceptional Conditions",
        ],
        "root_causes": [
            "Missing rate limiting or resource consumption quotas",
            "No depth limits on recursive operations",
            "Use of algorithms with worst-case exponential or unbounded complexity",
        ],
        "preventability": 3,
        "preventability_rationale": "Rate limiting patterns exist but need consistent application",
    },
    "HTTP Request Manipulation": {
        "cwes": ["CWE-444", "CWE-93", "CWE-113"],
        "owasp_2025": [
            "A05:2025 - Injection",
            "A02:2025 - Security Misconfiguration",
        ],
        "root_causes": [
            "CRLF characters not stripped from user input before header construction",
            "Inconsistent HTTP parsing rules between proxy/load-balancer and backend",
            "Missing request validation or normalization at gateway level",
        ],
        "preventability": 3,
        "preventability_rationale": "Requires consistent parsing config across proxy and backend",
    },
    "Phishing / Spoofing": {
        "cwes": ["CWE-451", "CWE-345"],
        "owasp_2025": [
            "A06:2025 - Insecure Design",
            "A07:2025 - Authentication Failures",
        ],
        "root_causes": [
            "Missing email authentication controls (DMARC, SPF, DKIM)",
            "UI design that does not distinguish trusted from untrusted content",
            "Unvalidated redirect/forward destinations controlled by user input",
        ],
        "preventability": 2,
        "preventability_rationale": "Technical controls (DMARC/SPF) exist, but social engineering is partly outside developer control",
    },
    "Supply Chain / Third-Party": {
        "cwes": ["CWE-1035", "CWE-829", "CWE-506"],
        "owasp_2025": [
            "A03:2025 - Software Supply Chain Failures",
            "A08:2025 - Software or Data Integrity Failures",
        ],
        "root_causes": [
            "No dependency vulnerability scanning (SCA) in CI/CD pipeline",
            "Missing integrity verification of third-party packages and updates",
            "No software bill of materials (SBOM) or dependency inventory",
            "Lack of pinning or lock files for transitive dependencies",
        ],
        "preventability": 3,
        "preventability_rationale": "SCA tooling exists but requires adoption and monitoring",
    },

    "Cross-site Scripting (XSS) - Stored": {
        "cwes": ["CWE-79"],
        "owasp_2025": ["A05:2025 - Injection"],
        "root_causes": [
            "Stored user input rendered without context-aware output encoding",
            "No sanitization library applied to persisted HTML content before rendering",
            "Missing Content-Security-Policy headers",
        ],
        "preventability": 4,
        "preventability_rationale": "Same framework auto-escaping protections as other XSS variants",
    },
    "Cross-site Scripting (XSS) - DOM": {
        "cwes": ["CWE-79", "CWE-116"],
        "owasp_2025": ["A05:2025 - Injection"],
        "root_causes": [
            "Unsafe assignment to innerHTML or document.write with user-controlled data",
            "Missing client-side output encoding before DOM manipulation",
            "No Content-Security-Policy restricting inline scripts and eval",
        ],
        "preventability": 3,
        "preventability_rationale": "Client-side, harder for server frameworks to catch",
    },
    "Cross-Site Request Forgery (CSRF)": {
        "cwes": ["CWE-352"],
        "owasp_2025": ["A01:2025 - Broken Access Control"],
        "root_causes": [
            "Missing anti-CSRF tokens on state-changing requests",
            "SameSite cookie attribute not set to Strict or Lax",
            "No origin or referer header validation on sensitive endpoints",
        ],
        "preventability": 5,
        "preventability_rationale": "Framework CSRF middleware on by default",
    },
    "Insecure Direct Object Reference (IDOR)": {
        "cwes": ["CWE-639", "CWE-284"],
        "owasp_2025": ["A01:2025 - Broken Access Control"],
        "root_causes": [
            "Missing ownership or authorization check before returning objects by user-supplied ID",
            "Predictable or sequential object identifiers without access control enforcement",
            "No server-side authorization verification after authentication",
        ],
        "preventability": 3,
        "preventability_rationale": "Clear pattern (object-level auth checks); requires consistent application",
    },
    "Open Redirect": {
        "cwes": ["CWE-601"],
        "owasp_2025": ["A01:2025 - Broken Access Control"],
        "root_causes": [
            "User-supplied redirect destinations not validated against an allowlist",
            "No restriction of redirect targets to same-origin or trusted domains",
            "Redirect functionality in authentication or logout flows lacks destination validation",
        ],
        "preventability": 4,
        "preventability_rationale": "Allowlisting is a clear pattern but requires explicit implementation, not a default",
    },
    "UI Redressing (Clickjacking)": {
        "cwes": ["CWE-1021"],
        "owasp_2025": ["A02:2025 - Security Misconfiguration"],
        "root_causes": [
            "Missing X-Frame-Options or Content-Security-Policy frame-ancestors header",
            "Application can be embedded in cross-origin iframes without restriction",
            "No frame-busting protection on sensitive user interaction pages",
        ],
        "preventability": 5,
        "preventability_rationale": "Single header/CSP directive prevents it",
    },
    "Deserialization of Untrusted Data": {
        "cwes": ["CWE-502"],
        "owasp_2025": ["A08:2025 - Software or Data Integrity Failures"],
        "root_causes": [
            "Deserializing user-controlled data using unsafe native serialization formats",
            "Missing integrity checks or signatures on serialized payloads",
            "No allowlist of permitted types during deserialization",
        ],
        "preventability": 3,
        "preventability_rationale": "Requires awareness and type allowlisting",
    },
    "Business Logic Errors": {
        "cwes": ["CWE-840", "CWE-841"],
        "owasp_2025": ["A06:2025 - Insecure Design"],
        "root_causes": [
            "No threat modeling or security review of business workflows",
            "Missing server-side enforcement of state machine or workflow transitions",
            "Assumptions about intended user behaviour not validated at the server side",
        ],
        "preventability": 1,
        "preventability_rationale": "No framework or tool can prevent domain-specific logic mistakes",
    },
    "Violation of Secure Design Principles": {
        "cwes": ["CWE-657", "CWE-693"],
        "owasp_2025": ["A06:2025 - Insecure Design"],
        "root_causes": [
            "Security requirements not defined or reviewed during design phase",
            "Defense-in-depth and least-privilege principles not applied architecturally",
            "Security controls absent or bypassable due to fundamental design oversights",
        ],
        "preventability": 1,
        "preventability_rationale": "Requires security architecture expertise from day one; no automated prevention",
    },
}


# Preventability scale legend
PREVENTABILITY_SCALE = {
    1: "Very Hard - requires domain-specific expertise; no systematic prevention approach exists",
    2: "Hard - requires careful upfront design; easy to miss even with awareness",
    3: "Moderate - established prevention patterns exist but require consistent discipline",
    4: "Easy - standard frameworks and tooling prevent it when used correctly",
    5: "Very Easy - modern framework defaults prevent it; requires opting into the vulnerability",
}
