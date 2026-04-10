# GEMINI.md - Researcher's Context for Gemini Agents

This file provides a high-level technical overview of the **DepVuln Triage Environment** for future Gemini agents working on this codebase.

## Project Essence
DepVuln is an **OpenEnv** environment designed for the **ScalarHack** (OpenEnv Round 1). It simulates a security engineering role where an AI agent must triage dependency vulnerabilities (CVEs) within a specific project context.

- **Objective**: Analyze CVEs, assess their actual severity based on how the project uses the dependency, and recommend remediation steps.
- **Key Metric**: `score` [0.0 - 1.0], assessing both accuracy of severity assessment and the feasibility of remediation actions.

## Core Technical Stack
- **Framework**: `openenv-core` (standard gymnasium-like `step()` / `reset()` interface for AI agents).
- **Server**: FastAPI serving at port 7860 (HuggingFace Space standard).
- **Communication**: WebSocket (stateful) and HTTP (stateless) support.
- **Models**: Pydantic v2 classes in `models.py`.
- **Package Manager**: `uv` (standard for modern Python projects).

## Environment Mechanics

### Action Space (`DepVulnAction`)
Agents interact using these 5 commands:
1. `analyze_cve(cve_id)`: Fetches detailed vulnerability info and fix versions.
2. `check_upgrade(package_name, target_version)`: Checks for breaking changes in dependency upgrades.
3. `assess_severity(cve_id, severity, reasoning)`: Sets contextual severity (critical/high/medium/low/none).
4. `recommend_action(cve_id, action_type, details)`: Recommends fix (upgrade/patch/accept_risk/replace).
5. `submit_report()`: Ends the episode and calculates the final score.

### Observation Space (`DepVulnObservation`)
Provides the agent with:
- **Project Context**: Language, type (CLI, web API, service), and description.
- **Dependency Data**: Versions, purposes, and a full dependency tree.
- **CVE Reports**: CVSS scores, summaries, and affected versions.

## Task Design (`server/tasks.py`)
There are three tasks defined with increasing difficulty:
1. **`single_cve` (Easy)**: A simple web API with one clear critical vulnerability.
2. **`multi_cve_triage` (Medium)**: Tests "context-awareness." Includes false positives (e.g., an XSS bug in a tool that doesn't render HTML).
3. **`dependency_hell` (Hard)**: Tests complex version logic. Upgrading one package to fix a CVE might break another dependant package.

## Scoring Logic (`server/graders.py`)
Scoring is deterministic and based on a "Ground Truth" for each task.
- **Severity Distance**: Partial credit for being "one step off" (e.g., assessing 'high' when it's actually 'critical' vs 'none').
- **Remediation Quality**: Rewards correct upgrade paths; penalizes dangerous risk acceptance or unnecessary over-triaging.
- **Diligence Bonus**: Small rewards for calling `analyze_cve` before making assessments.

## Development & Deployment
- **Local Testing**: Build with `Dockerfile`, then run `inference.py` to test the baseline agent.
- **Validation**: Run `./validate-submission.sh` to ensure OpenEnv spec compliance.
- **Style**: The owner (Sharooq) prefers manual/casual/direct communication. No AI "fluff."

## Files to Watch
- `server/depvuln_environment.py`: The heart of the simulation.
- `server/tasks.py`: Change this to add new vulnerability scenarios.
- `server/graders.py`: Tweak this to adjust how agents are evaluated.
- `models.py`: Defines the interface between agent and environment.
