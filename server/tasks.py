# Copyright (c) 2026. All rights reserved.
# DepVuln Triage Environment - Task Definitions

"""
Three tasks ranging from easy to hard:
  1. single_cve       - One dependency, one critical CVE, clear fix
  2. multi_cve_triage - Multiple deps, mixed CVEs, false positives
  3. dependency_hell   - Transitive deps with upgrade conflicts
"""

from typing import Any, Dict, List

# ─────────────────────────────────────────────────────────
# Task 1: Single CVE (Easy)
# ─────────────────────────────────────────────────────────

TASK_EASY = {
    "name": "single_cve",
    "description": "A web API project with one critical vulnerability in a core dependency.",
    "max_steps": 12,
    "project": {
        "name": "payment-gateway-api",
        "language": "python",
        "type": "web-api",
        "description": "REST API handling payment processing for e-commerce clients.",
    },
    "dependencies": [
        {
            "name": "fastapi",
            "version": "0.95.0",
            "direct": True,
            "purpose": "Web framework for the REST API",
        },
        {
            "name": "sqlalchemy",
            "version": "1.4.41",
            "direct": True,
            "purpose": "ORM for database operations",
        },
        {
            "name": "pydantic",
            "version": "1.10.7",
            "direct": True,
            "purpose": "Data validation and serialization",
        },
    ],
    "dependency_tree": {
        "fastapi": ["starlette", "pydantic"],
        "sqlalchemy": [],
        "pydantic": [],
    },
    "cves": [
        {
            "id": "CVE-2024-24762",
            "package": "fastapi",
            "cvss_score": 7.5,
            "cvss_severity": "high",
            "summary": "Denial of Service via multipart form data parsing in FastAPI < 0.109.1",
            "affected_versions": "<0.109.1",
            "fix_version": "0.109.1",
            "attack_vector": "network",
            "description": (
                "FastAPI versions before 0.109.1 are vulnerable to a denial "
                "of service attack through specially crafted multipart form "
                "data. An attacker can send a malicious request that causes "
                "excessive CPU consumption, making the server unresponsive. "
                "This affects any FastAPI application that accepts file "
                "uploads or multipart form data."
            ),
            "references": [
                "https://github.com/tiangolo/fastapi/security/advisories/GHSA-qf9m-vfgh-m389"
            ],
        }
    ],
    # Ground truth for grading
    "ground_truth": {
        "CVE-2024-24762": {
            "correct_severity": "high",
            "correct_action": "upgrade",
            "is_false_positive": False,
            "severity_reasoning": (
                "Network-accessible DoS on a payment API is high severity. "
                "Payment processing downtime directly impacts revenue."
            ),
            "action_details": "Upgrade fastapi from 0.95.0 to >=0.109.1",
        }
    },
}


# ─────────────────────────────────────────────────────────
# Task 2: Multi-CVE Triage (Medium)
# ─────────────────────────────────────────────────────────

TASK_MEDIUM = {
    "name": "multi_cve_triage",
    "description": (
        "A data processing CLI tool with multiple dependencies and CVEs. "
        "Some CVEs are false positives in this context."
    ),
    "max_steps": 20,
    "project": {
        "name": "etl-pipeline-cli",
        "language": "python",
        "type": "cli-tool",
        "description": (
            "Command-line ETL tool that reads CSV/JSON files from local "
            "disk, transforms data, and writes to a PostgreSQL database. "
            "Runs on internal servers only. No network-facing endpoints."
        ),
    },
    "dependencies": [
        {
            "name": "pandas",
            "version": "1.5.3",
            "direct": True,
            "purpose": "Data manipulation and transformation",
        },
        {
            "name": "psycopg2",
            "version": "2.9.5",
            "direct": True,
            "purpose": "PostgreSQL database driver",
        },
        {
            "name": "requests",
            "version": "2.28.0",
            "direct": True,
            "purpose": "HTTP client for downloading config files on startup",
        },
        {
            "name": "jinja2",
            "version": "3.1.1",
            "direct": True,
            "purpose": "Template engine for generating SQL queries from templates",
        },
        {
            "name": "cryptography",
            "version": "39.0.0",
            "direct": True,
            "purpose": "Encrypting database credentials at rest",
        },
    ],
    "dependency_tree": {
        "pandas": ["numpy"],
        "psycopg2": [],
        "requests": ["urllib3", "certifi"],
        "jinja2": ["markupsafe"],
        "cryptography": ["cffi"],
    },
    "cves": [
        {
            "id": "CVE-2023-43804",
            "package": "urllib3",
            "cvss_score": 8.1,
            "cvss_severity": "high",
            "summary": "Cookie and Authorization header leak on cross-origin redirects in urllib3",
            "affected_versions": "<2.0.6",
            "fix_version": "2.0.6",
            "attack_vector": "network",
            "description": (
                "urllib3 before 2.0.6 leaks the Proxy-Authorization header "
                "to origins during cross-origin redirects. An attacker who "
                "controls a redirect target can steal authentication tokens."
            ),
        },
        {
            "id": "CVE-2024-22195",
            "package": "jinja2",
            "cvss_score": 6.1,
            "cvss_severity": "medium",
            "summary": "Cross-site scripting (XSS) via template rendering in Jinja2",
            "affected_versions": "<3.1.3",
            "fix_version": "3.1.3",
            "attack_vector": "network",
            "description": (
                "Jinja2 before 3.1.3 allows XSS attacks through "
                "xmlattr filter. If user-controlled data flows into "
                "HTML template rendering, an attacker can inject scripts."
            ),
        },
        {
            "id": "CVE-2023-49083",
            "package": "cryptography",
            "cvss_score": 7.5,
            "cvss_severity": "high",
            "summary": "NULL pointer dereference when loading PKCS7 certificates in cryptography",
            "affected_versions": "<41.0.6",
            "fix_version": "41.0.6",
            "attack_vector": "network",
            "description": (
                "The cryptography package before 41.0.6 has a NULL pointer "
                "dereference when loading certain malformed PKCS7 "
                "certificates. Processing untrusted certificate data can "
                "crash the application."
            ),
        },
        {
            "id": "CVE-2023-32681",
            "package": "requests",
            "cvss_score": 6.1,
            "cvss_severity": "medium",
            "summary": "Leaking Proxy-Authorization header to destination server on redirects",
            "affected_versions": "<2.31.0",
            "fix_version": "2.31.0",
            "attack_vector": "network",
            "description": (
                "Requests before 2.31.0 leaks Proxy-Authorization headers "
                "when redirected to an HTTPS endpoint. Sensitive proxy "
                "credentials can be exposed to the destination server."
            ),
        },
        {
            "id": "CVE-2024-37891",
            "package": "urllib3",
            "cvss_score": 4.4,
            "cvss_severity": "medium",
            "summary": "Proxy-Authorization header not stripped on cross-origin redirects",
            "affected_versions": "<2.2.2",
            "fix_version": "2.2.2",
            "attack_vector": "network",
            "description": (
                "urllib3 before 2.2.2 does not strip the "
                "Proxy-Authorization header during cross-origin redirects. "
                "Lower impact variant of CVE-2023-43804."
            ),
        },
    ],
    "ground_truth": {
        "CVE-2023-43804": {
            "correct_severity": "low",
            "correct_action": "accept_risk",
            "is_false_positive": True,
            "severity_reasoning": (
                "The CLI tool only makes outbound HTTP calls to a known "
                "internal config server on startup. No user-controlled "
                "redirects are possible, so header leak is not exploitable."
            ),
        },
        "CVE-2024-22195": {
            "correct_severity": "none",
            "correct_action": "accept_risk",
            "is_false_positive": True,
            "severity_reasoning": (
                "XSS requires rendering templates in a browser context. "
                "This CLI tool uses Jinja2 only for SQL query generation, "
                "never for HTML output. XSS is not exploitable."
            ),
        },
        "CVE-2023-49083": {
            "correct_severity": "medium",
            "correct_action": "upgrade",
            "is_false_positive": False,
            "severity_reasoning": (
                "The tool uses cryptography for credential encryption. "
                "While it does not process untrusted certificates directly, "
                "upgrading is prudent to prevent future misuse."
            ),
            "action_details": "Upgrade cryptography from 39.0.0 to >=41.0.6",
        },
        "CVE-2023-32681": {
            "correct_severity": "low",
            "correct_action": "upgrade",
            "is_false_positive": False,
            "severity_reasoning": (
                "Internal-only HTTP calls limit exposure, but upgrading "
                "requests is low effort and good practice."
            ),
            "action_details": "Upgrade requests from 2.28.0 to >=2.31.0",
        },
        "CVE-2024-37891": {
            "correct_severity": "low",
            "correct_action": "accept_risk",
            "is_false_positive": True,
            "severity_reasoning": (
                "Lower-impact duplicate of the urllib3 header leak. "
                "Same context applies: no user-controlled redirects."
            ),
        },
    },
}


# ─────────────────────────────────────────────────────────
# Task 3: Dependency Hell (Hard)
# ─────────────────────────────────────────────────────────

TASK_HARD = {
    "name": "dependency_hell",
    "description": (
        "A microservice with transitive dependency conflicts. "
        "Fixing one CVE breaks another package. Agent must find "
        "the optimal resolution path."
    ),
    "max_steps": 25,
    "project": {
        "name": "auth-service",
        "language": "python",
        "type": "web-service",
        "description": (
            "Authentication microservice handling OAuth2, JWT token "
            "issuance, and user session management. Internet-facing, "
            "processes untrusted input from login forms. High security "
            "requirements due to handling of credentials."
        ),
    },
    "dependencies": [
        {
            "name": "flask",
            "version": "2.2.5",
            "direct": True,
            "purpose": "Web framework for auth endpoints",
        },
        {
            "name": "pyjwt",
            "version": "2.6.0",
            "direct": True,
            "purpose": "JWT token creation and validation",
        },
        {
            "name": "authlib",
            "version": "1.2.0",
            "direct": True,
            "purpose": "OAuth2 provider implementation",
        },
        {
            "name": "cryptography",
            "version": "38.0.4",
            "direct": True,
            "purpose": "Cryptographic operations for token signing",
        },
        {
            "name": "redis",
            "version": "4.5.1",
            "direct": True,
            "purpose": "Session store and rate limiting",
        },
        {
            "name": "celery",
            "version": "5.2.7",
            "direct": True,
            "purpose": "Async task queue for email notifications",
        },
    ],
    "dependency_tree": {
        "flask": ["werkzeug", "jinja2", "markupsafe"],
        "pyjwt": ["cryptography"],
        "authlib": ["cryptography", "requests"],
        "cryptography": ["cffi"],
        "redis": [],
        "celery": ["kombu", "billiard", "vine"],
        "kombu": ["amqp"],
    },
    "cves": [
        {
            "id": "CVE-2023-49083",
            "package": "cryptography",
            "cvss_score": 7.5,
            "cvss_severity": "high",
            "summary": "NULL pointer dereference in PKCS7 certificate parsing",
            "affected_versions": "<41.0.6",
            "fix_version": "41.0.6",
            "attack_vector": "network",
            "description": (
                "cryptography < 41.0.6 has a NULL pointer dereference when "
                "loading malformed PKCS7 certs. In an auth service that "
                "processes certificates, this can crash the server."
            ),
        },
        {
            "id": "CVE-2023-46136",
            "package": "werkzeug",
            "cvss_score": 7.5,
            "cvss_severity": "high",
            "summary": "Denial of Service via large multipart form data in Werkzeug",
            "affected_versions": "<3.0.1",
            "fix_version": "3.0.1",
            "attack_vector": "network",
            "description": (
                "Werkzeug < 3.0.1 is vulnerable to resource exhaustion "
                "via specially crafted multipart requests. Login forms "
                "accepting file uploads are directly affected."
            ),
        },
        {
            "id": "CVE-2024-22195",
            "package": "jinja2",
            "cvss_score": 6.1,
            "cvss_severity": "medium",
            "summary": "XSS via xmlattr filter in Jinja2",
            "affected_versions": "<3.1.3",
            "fix_version": "3.1.3",
            "attack_vector": "network",
            "description": (
                "Jinja2 < 3.1.3 allows XSS through the xmlattr filter. "
                "If the auth service renders any user-facing HTML (login "
                "pages, error pages), this is exploitable."
            ),
        },
        {
            "id": "CVE-2024-34069",
            "package": "werkzeug",
            "cvss_score": 7.5,
            "cvss_severity": "high",
            "summary": "Remote code execution via debugger in Werkzeug",
            "affected_versions": "<3.0.3",
            "fix_version": "3.0.3",
            "attack_vector": "network",
            "description": (
                "Werkzeug debugger before 3.0.3 can be exploited for "
                "remote code execution if the debugger is enabled in "
                "production. The debugger PIN can be calculated from "
                "known server properties."
            ),
        },
        {
            "id": "CVE-2023-23934",
            "package": "werkzeug",
            "cvss_score": 3.5,
            "cvss_severity": "low",
            "summary": "Cookie parsing flaw allows setting cookies for other domains",
            "affected_versions": "<2.2.3",
            "fix_version": "2.2.3",
            "attack_vector": "network",
            "description": (
                "Werkzeug < 2.2.3 does not properly parse cookie names "
                "containing the '=' character, potentially allowing "
                "attackers to shadow legitimate cookies."
            ),
        },
        {
            "id": "CVE-2024-26130",
            "package": "cryptography",
            "cvss_score": 7.5,
            "cvss_severity": "high",
            "summary": "NULL pointer dereference in PKCS12 key deserialization",
            "affected_versions": "<42.0.4",
            "fix_version": "42.0.4",
            "attack_vector": "network",
            "description": (
                "cryptography < 42.0.4 crashes when deserializing certain "
                "malformed PKCS12 key bundles. An attacker supplying a "
                "crafted key bundle can trigger a denial of service."
            ),
        },
    ],
    # Upgrade constraints that create the "hell"
    "upgrade_constraints": {
        "werkzeug": {
            "3.0.3": {
                "compatible_with": {"flask": ">=3.0.0"},
                "breaks": ["flask==2.2.5"],
                "notes": (
                    "Werkzeug 3.0.3 requires Flask >= 3.0.0. "
                    "Upgrading Flask to 3.0.0 also requires upgrading "
                    "Jinja2 to >= 3.1.2 and MarkupSafe to >= 2.1.3."
                ),
            },
            "2.2.3": {
                "compatible_with": {"flask": ">=2.2.0"},
                "breaks": [],
                "notes": (
                    "Werkzeug 2.2.3 is compatible with Flask 2.2.5. "
                    "Fixes CVE-2023-23934 but NOT CVE-2023-46136 or CVE-2024-34069."
                ),
            },
        },
        "cryptography": {
            "42.0.4": {
                "compatible_with": {"pyjwt": ">=2.8.0", "authlib": ">=1.3.0"},
                "breaks": ["pyjwt==2.6.0", "authlib==1.2.0"],
                "notes": (
                    "cryptography 42.0.4 changes the RSA key API. "
                    "PyJWT must be >= 2.8.0 and authlib >= 1.3.0 for "
                    "compatibility. Both upgrades are safe."
                ),
            },
            "41.0.6": {
                "compatible_with": {"pyjwt": ">=2.6.0", "authlib": ">=1.2.0"},
                "breaks": [],
                "notes": (
                    "cryptography 41.0.6 is compatible with current "
                    "pyjwt and authlib. Fixes CVE-2023-49083 but NOT "
                    "CVE-2024-26130."
                ),
            },
        },
        "flask": {
            "3.0.0": {
                "compatible_with": {"werkzeug": ">=3.0.0"},
                "breaks": [],
                "notes": (
                    "Flask 3.0.0 requires Werkzeug >= 3.0.0. This is a "
                    "major version upgrade with breaking changes to the "
                    "application factory pattern."
                ),
            },
        },
    },
    "ground_truth": {
        "CVE-2023-49083": {
            "correct_severity": "high",
            "correct_action": "upgrade",
            "is_false_positive": False,
            "severity_reasoning": (
                "Auth service processes certificates for OAuth2. "
                "A crash from malformed cert data is a real DoS risk."
            ),
            "action_details": (
                "Upgrade cryptography to 42.0.4 (fixes both CVEs). "
                "Also upgrade pyjwt to >=2.8.0 and authlib to >=1.3.0."
            ),
        },
        "CVE-2023-46136": {
            "correct_severity": "high",
            "correct_action": "upgrade",
            "is_false_positive": False,
            "severity_reasoning": (
                "Login forms accept POST data. DoS via multipart is "
                "directly exploitable on an internet-facing auth service."
            ),
            "action_details": (
                "Upgrade werkzeug to 3.0.3 (fixes all werkzeug CVEs). "
                "Requires upgrading flask to 3.0.0, jinja2 to >=3.1.3, "
                "and markupsafe to >=2.1.3."
            ),
        },
        "CVE-2024-22195": {
            "correct_severity": "medium",
            "correct_action": "upgrade",
            "is_false_positive": False,
            "severity_reasoning": (
                "Auth service likely renders login/error pages with Jinja2. "
                "XSS on login pages is a credential theft risk."
            ),
            "action_details": "Upgrade jinja2 to >=3.1.3",
        },
        "CVE-2024-34069": {
            "correct_severity": "critical",
            "correct_action": "upgrade",
            "is_false_positive": False,
            "severity_reasoning": (
                "RCE via debugger is critical if debugger is ever enabled. "
                "Even if disabled in prod, the fix is essential as a "
                "defense-in-depth measure for an auth service."
            ),
            "action_details": (
                "Upgrade werkzeug to 3.0.3. Same upgrade path as "
                "CVE-2023-46136 resolution."
            ),
        },
        "CVE-2023-23934": {
            "correct_severity": "medium",
            "correct_action": "upgrade",
            "is_false_positive": False,
            "severity_reasoning": (
                "Cookie shadowing on an auth service could enable "
                "session fixation. Moderate risk, fix is included in "
                "the werkzeug 3.0.3 upgrade anyway."
            ),
            "action_details": "Covered by werkzeug upgrade to 3.0.3",
        },
        "CVE-2024-26130": {
            "correct_severity": "high",
            "correct_action": "upgrade",
            "is_false_positive": False,
            "severity_reasoning": (
                "PKCS12 deserialization crash in an auth service that "
                "handles key bundles is a clear DoS vector."
            ),
            "action_details": (
                "Upgrade cryptography to 42.0.4. Requires upgrading "
                "pyjwt to >=2.8.0 and authlib to >=1.3.0."
            ),
        },
    },
}


TASKS = {
    "single_cve": TASK_EASY,
    "multi_cve_triage": TASK_MEDIUM,
    "dependency_hell": TASK_HARD,
}


def get_task(name: str) -> Dict[str, Any]:
    """Get task definition by name."""
    if name not in TASKS:
        raise ValueError(f"Unknown task: {name}. Available: {list(TASKS.keys())}")
    return TASKS[name]


def list_tasks() -> List[str]:
    """Return all available task names."""
    return list(TASKS.keys())
