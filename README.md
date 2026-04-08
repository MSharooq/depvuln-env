---
title: DepVuln Triage Environment
emoji: 🔒
colorFrom: red
colorTo: red
sdk: docker
app_port: 7860
tags:
  - openenv
  - security
  - vulnerability
  - triage
pinned: false
license: bsd-3-clause
---

# DepVuln: Dependency Vulnerability Triage Environment

An OpenEnv environment where AI agents play the role of a security engineer triaging CVEs found in a project's dependency tree. Every software team deals with vulnerability alerts. Most of the work isn't just reading CVSS scores; it's understanding whether a CVE actually matters *in context* and deciding the right fix.

This environment tests exactly that skill.

## Why This Matters

Dependency vulnerability triage is one of the most common and time-consuming tasks in software engineering. Tools like Dependabot and Snyk generate hundreds of alerts, but **context-aware prioritization** is still a human bottleneck. An agent that can accurately assess "this high-severity CVE is actually a false positive because we only use this library for offline processing" would save thousands of engineering hours across the industry.

## How It Works

The agent receives:
- Project metadata (name, type, language, description)
- A list of dependencies with versions and purposes
- A dependency tree showing transitive relationships
- CVE reports with CVSS scores, summaries, and affected versions

The agent must:
1. **Analyze** each CVE to understand the technical details
2. **Check upgrade paths** when needed (some upgrades break things)
3. **Assess severity in context** (a network-exploitable bug doesn't matter in a CLI tool)
4. **Recommend actions** (upgrade, patch, accept risk, or replace the package)
5. **Submit a final triage report**

## Action Space

| Command | Parameters | Description |
|---------|-----------|-------------|
| `analyze_cve` | `cve_id` | Get detailed CVE description, fix version, references |
| `check_upgrade` | `package_name`, `target_version` | Check compatibility of an upgrade path |
| `assess_severity` | `cve_id`, `severity`, `reasoning` | Declare contextual severity (critical/high/medium/low/none) |
| `recommend_action` | `cve_id`, `action_type`, `details` | Recommend fix (upgrade/patch/accept_risk/replace) |
| `submit_report` | none | Finalize triage and get scored |

Actions are JSON objects sent to `env.step()`:
```json
{"command": "analyze_cve", "cve_id": "CVE-2024-24762"}
{"command": "assess_severity", "cve_id": "CVE-2024-24762", "severity": "high", "reasoning": "DoS on internet-facing payment API"}
{"command": "recommend_action", "cve_id": "CVE-2024-24762", "action_type": "upgrade", "details": "Upgrade fastapi to >=0.109.1"}
{"command": "submit_report"}
```

## Observation Space

Each observation includes:
- `project_info`: dict with name, language, type, description
- `dependencies`: list of {name, version, direct, purpose}
- `cves`: list of {id, package, cvss_score, cvss_severity, summary, affected_versions, attack_vector}
- `dependency_tree`: dict mapping package to its transitive deps
- `analysis_result`: detailed CVE info (after analyze_cve)
- `upgrade_info`: compatibility check result (after check_upgrade)
- `assessment_feedback`: confirmation of recorded assessment
- `recommendation_feedback`: confirmation of recorded recommendation
- `report_summary`: final score breakdown (after submit_report)
- `steps_remaining`: how many actions the agent has left
- `error`: error message if a command failed

## Tasks

### Task 1: `single_cve` (Easy)
A payment gateway API using FastAPI with one critical DoS vulnerability. Clear fix available. Tests basic triage flow: analyze, assess, recommend, submit.

**Expected difficulty**: Any capable model should score > 0.7.

### Task 2: `multi_cve_triage` (Medium)
A CLI-based ETL tool with 5 dependencies and 5 CVEs. The twist: several CVEs are **false positives in context**. An XSS vulnerability in Jinja2 doesn't matter when Jinja2 is only used for SQL template generation, not HTML rendering. A network header leak doesn't matter when the tool only talks to one internal server.

**Expected difficulty**: Requires reasoning about project context. Models that blindly trust CVSS scores will over-triage and lose points.

### Task 3: `dependency_hell` (Hard)
An internet-facing auth service with 6 dependencies, 6 CVEs, and **transitive dependency conflicts**. Upgrading cryptography to fix two CVEs requires upgrading PyJWT and authlib. Upgrading Werkzeug to fix three CVEs requires upgrading Flask, which requires upgrading Jinja2. The agent must find the optimal resolution path across interconnected upgrades.

**Expected difficulty**: Challenges frontier models. Requires multi-step planning and constraint reasoning.

## Reward Design

Rewards flow throughout the episode, not just at the end:

- **`analyze_cve`**: +0.02 per CVE analyzed (information gathering)
- **`check_upgrade`**: +0.02 per upgrade path checked
- **`assess_severity`**: 0.0 to 0.1 based on accuracy (partial credit via severity distance)
- **`recommend_action`**: 0.0 to 0.15 based on accuracy
- **`submit_report`**: final computed score in [0.0, 1.0]

Penalties:
- -0.02 for invalid commands or missing parameters
- -0.05 for unknown commands
- Coverage penalty for unaddressed CVEs
- Noise penalty for recommendations on non-existent CVEs
- -0.1 penalty if episode times out without voluntary submission

## Setup & Usage

### Install
```bash
pip install openenv-core
pip install git+https://huggingface.co/spaces/<your-space>/depvuln-env
```

### Run locally
```bash
# Build and run the Docker container
docker build -t depvuln-env .
docker run -p 8000:7860 -e PORT=7860 depvuln-env

# In another terminal
python inference.py
```

### Connect to HF Space
```python
import asyncio
from depvuln_env import DepVulnAction, DepVulnEnv

async def main():
    async with DepVulnEnv(base_url="https://<your-space>.hf.space") as env:
        result = await env.reset(task="single_cve")
        print(result.observation.project_info)
        print(result.observation.cves)

        result = await env.step(DepVulnAction(
            command="analyze_cve",
            cve_id="CVE-2024-24762"
        ))
        print(result.observation.analysis_result)

asyncio.run(main())
```

### Run inference
```bash
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="Qwen/Qwen2.5-72B-Instruct"
export HF_TOKEN="your-token"
export IMAGE_NAME="depvuln-env"

python inference.py
```

## Baseline Scores

| Task | Qwen2.5-72B-Instruct | Description |
|------|----------------------|-------------|
| single_cve | ~0.75 | Straightforward triage |
| multi_cve_triage | ~0.45 | Misses some false positives |
| dependency_hell | ~0.30 | Struggles with constraint reasoning |
| **Average** | **~0.50** | |

*Scores are approximate and may vary with temperature settings.*

## Project Structure
```
depvuln_env/
├── __init__.py              # Package exports
├── models.py                # DepVulnAction, DepVulnObservation, DepVulnState
├── client.py                # DepVulnEnv (EnvClient subclass)
├── openenv.yaml             # Environment manifest
├── pyproject.toml           # Dependencies
├── inference.py             # Baseline inference script
├── Dockerfile               # Container image
├── README.md                # This file
└── server/
    ├── __init__.py
    ├── app.py               # FastAPI application
    ├── depvuln_environment.py  # Core environment logic
    ├── tasks.py              # Task definitions with CVE data
    ├── graders.py            # Deterministic grading logic
    └── requirements.txt      # Server dependencies
```

## License

BSD-3-Clause
