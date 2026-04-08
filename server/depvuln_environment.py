# Copyright (c) 2026. All rights reserved.
# DepVuln Triage Environment - Core Environment

import os
from typing import Any, Dict, Optional
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

# Import from sibling modules (server package)
from .graders import (
    compute_episode_score,
    grade_assessment,
    grade_recommendation,
)
from .tasks import TASKS, get_task, list_tasks

# Import models from root level
from models import DepVulnAction, DepVulnObservation, DepVulnState


class DepVulnEnvironment(Environment):
    """Dependency Vulnerability Triage environment.

    The agent plays a security engineer triaging CVEs found in a project's
    dependency tree. It must analyze vulnerabilities in context, assess real
    severity, and recommend appropriate remediation actions.
    """

    def __init__(self) -> None:
        super().__init__()
        self._task_name: str = os.getenv("DEPVULN_TASK", "single_cve")
        self._task: Dict[str, Any] = {}
        self._step_count: int = 0
        self._max_steps: int = 20
        self._episode_id: Optional[str] = None
        self._done: bool = False

        # Agent progress tracking
        self._assessments: Dict[str, str] = {}  # cve_id -> severity
        self._recommendations: Dict[str, str] = {}  # cve_id -> action
        self._analyzed_cves: set = set()
        self._checked_upgrades: set = set()  # (package, version) pairs
        self._cumulative_reward: float = 0.0
        self._step_rewards: list = []

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> DepVulnObservation:
        """Reset environment for a new triage episode."""
        # Allow task override via kwargs or env var
        task_name = kwargs.get("task", self._task_name)
        if task_name not in TASKS:
            task_name = "single_cve"

        self._task_name = task_name
        self._task = get_task(task_name)
        self._max_steps = self._task.get("max_steps", 20)
        self._episode_id = episode_id or str(uuid4())
        self._step_count = 0
        self._done = False

        # Reset agent progress
        self._assessments = {}
        self._recommendations = {}
        self._analyzed_cves = set()
        self._checked_upgrades = set()
        self._cumulative_reward = 0.0
        self._step_rewards = []

        # Build initial observation with project context
        project = self._task["project"]
        deps = self._task["dependencies"]
        dep_tree = self._task.get("dependency_tree", {})

        # Strip fix_version and ground truth from CVE data shown to agent
        visible_cves = []
        for cve in self._task["cves"]:
            visible = {
                "id": cve["id"],
                "package": cve["package"],
                "cvss_score": cve["cvss_score"],
                "cvss_severity": cve["cvss_severity"],
                "summary": cve["summary"],
                "affected_versions": cve["affected_versions"],
                "attack_vector": cve["attack_vector"],
            }
            visible_cves.append(visible)

        return DepVulnObservation(
            done=False,
            reward=0.0,
            project_info=project,
            dependencies=deps,
            cves=visible_cves,
            dependency_tree=dep_tree,
            step_hint=(
                "Available commands: analyze_cve, check_upgrade, "
                "assess_severity, recommend_action, submit_report. "
                f"You have {self._max_steps} steps to triage all CVEs."
            ),
            task_name=task_name,
            steps_remaining=self._max_steps,
        )

    def step(
        self,
        action: DepVulnAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> DepVulnObservation:
        """Execute one agent action in the triage episode."""
        if self._done:
            return DepVulnObservation(
                done=True,
                reward=0.0,
                error="Episode is already done. Call reset() first.",
                steps_remaining=0,
            )

        self._step_count += 1
        remaining = self._max_steps - self._step_count

        command = action.command.lower().strip()
        reward = 0.0
        obs_kwargs: Dict[str, Any] = {}

        if command == "analyze_cve":
            reward, obs_kwargs = self._handle_analyze(action)
        elif command == "check_upgrade":
            reward, obs_kwargs = self._handle_check_upgrade(action)
        elif command == "assess_severity":
            reward, obs_kwargs = self._handle_assess(action)
        elif command == "recommend_action":
            reward, obs_kwargs = self._handle_recommend(action)
        elif command == "submit_report":
            reward, obs_kwargs = self._handle_submit()
        else:
            reward = -0.05
            obs_kwargs["error"] = (
                f"Unknown command: '{command}'. Valid commands: "
                "analyze_cve, check_upgrade, assess_severity, "
                "recommend_action, submit_report"
            )

        self._cumulative_reward += reward
        self._step_rewards.append(reward)

        # Force end if max steps reached
        if self._step_count >= self._max_steps and not self._done:
            self._done = True
            # Auto-submit on timeout
            final_score, details = compute_episode_score(
                self._assessments,
                self._recommendations,
                self._task["ground_truth"],
                self._task_name,
            )
            # Penalty for not submitting voluntarily
            final_score = max(0.0, final_score - 0.1)
            obs_kwargs["report_summary"] = (
                f"Episode ended (max steps). Auto-submitted. "
                f"Score: {final_score:.3f}"
            )
            reward = final_score
            self._step_rewards[-1] = reward

        return DepVulnObservation(
            done=self._done,
            reward=reward,
            steps_remaining=max(0, remaining),
            task_name=self._task_name,
            **obs_kwargs,
        )

    @property
    def state(self) -> DepVulnState:
        """Return current episode state."""
        return DepVulnState(
            episode_id=self._episode_id,
            step_count=self._step_count,
            task_name=self._task_name,
            assessed_cves=list(self._assessments.keys()),
            recommended_cves=list(self._recommendations.keys()),
            cumulative_reward=self._cumulative_reward,
            max_steps=self._max_steps,
        )

    # ─── Command Handlers ────────────────────────────────

    def _find_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up a CVE by ID in the current task."""
        for cve in self._task["cves"]:
            if cve["id"] == cve_id:
                return cve
        return None

    def _handle_analyze(self, action: DepVulnAction) -> tuple:
        """Provide detailed CVE analysis. Small reward for information gathering."""
        cve_id = action.cve_id
        if not cve_id:
            return -0.02, {"error": "analyze_cve requires cve_id parameter"}

        cve = self._find_cve(cve_id)
        if not cve:
            return -0.02, {"error": f"CVE {cve_id} not found in this project"}

        self._analyzed_cves.add(cve_id)

        # Provide the detailed description and fix version
        analysis = (
            f"CVE: {cve['id']}\n"
            f"Package: {cve['package']}\n"
            f"CVSS Score: {cve['cvss_score']} ({cve['cvss_severity']})\n"
            f"Attack Vector: {cve['attack_vector']}\n"
            f"Affected Versions: {cve['affected_versions']}\n"
            f"Fix Version: {cve.get('fix_version', 'No fix available')}\n"
            f"\nDescription:\n{cve['description']}\n"
        )

        if cve.get("references"):
            analysis += f"\nReferences: {', '.join(cve['references'])}"

        # Small reward for analyzing before assessing
        reward = 0.02
        return reward, {"analysis_result": analysis}

    def _handle_check_upgrade(self, action: DepVulnAction) -> tuple:
        """Check upgrade compatibility for a package."""
        pkg = action.package_name
        version = action.target_version
        if not pkg or not version:
            return -0.02, {
                "error": "check_upgrade requires package_name and target_version"
            }

        key = (pkg, version)
        self._checked_upgrades.add(key)

        constraints = self._task.get("upgrade_constraints", {})
        if pkg in constraints and version in constraints[pkg]:
            info = constraints[pkg][version]
            result = (
                f"Upgrade {pkg} to {version}:\n"
                f"  Compatible with: {info['compatible_with']}\n"
                f"  Breaks: {info['breaks'] if info['breaks'] else 'Nothing'}\n"
                f"  Notes: {info['notes']}"
            )
        else:
            # Default: upgrade is safe
            result = (
                f"Upgrade {pkg} to {version}: "
                f"No known compatibility issues found. Safe to upgrade."
            )

        return 0.02, {"upgrade_info": result}

    def _handle_assess(self, action: DepVulnAction) -> tuple:
        """Record and grade a severity assessment."""
        cve_id = action.cve_id
        severity = action.severity

        if not cve_id or not severity:
            return -0.02, {
                "error": "assess_severity requires cve_id and severity parameters"
            }

        if severity.lower() not in ("critical", "high", "medium", "low", "none"):
            return -0.02, {
                "error": f"Invalid severity: '{severity}'. "
                "Use: critical, high, medium, low, none"
            }

        cve = self._find_cve(cve_id)
        if not cve:
            return -0.02, {"error": f"CVE {cve_id} not found in this project"}

        # Record the assessment
        self._assessments[cve_id] = severity.lower()

        # Grade it immediately for partial reward
        score, explanation = grade_assessment(
            cve_id, severity, self._task["ground_truth"]
        )

        # Scale reward: 0.1 per correct assessment, proportional for partial
        reward = score * 0.1

        # Bonus if the agent analyzed the CVE first (shows diligence)
        if cve_id in self._analyzed_cves:
            reward += 0.01

        feedback = f"Assessment recorded for {cve_id}: severity={severity}."
        return reward, {"assessment_feedback": feedback}

    def _handle_recommend(self, action: DepVulnAction) -> tuple:
        """Record and grade a remediation recommendation."""
        cve_id = action.cve_id
        action_type = action.action_type

        if not cve_id or not action_type:
            return -0.02, {
                "error": "recommend_action requires cve_id and action_type"
            }

        cve = self._find_cve(cve_id)
        if not cve:
            return -0.02, {"error": f"CVE {cve_id} not found in this project"}

        self._recommendations[cve_id] = action_type.lower()

        score, explanation = grade_recommendation(
            cve_id, action_type, self._task["ground_truth"]
        )

        reward = score * 0.15

        feedback = (
            f"Recommendation recorded for {cve_id}: action={action_type}."
        )
        return reward, {"recommendation_feedback": feedback}

    def _handle_submit(self) -> tuple:
        """Submit final triage report and end episode."""
        self._done = True

        final_score, details = compute_episode_score(
            self._assessments,
            self._recommendations,
            self._task["ground_truth"],
            self._task_name,
        )

        # Build summary
        total = len(self._task["ground_truth"])
        assessed = len(self._assessments)
        recommended = len(self._recommendations)
        missed = details.get("missed_cves", [])

        summary = (
            f"Triage Report Submitted\n"
            f"{'=' * 40}\n"
            f"Task: {self._task_name}\n"
            f"CVEs assessed: {assessed}/{total}\n"
            f"CVEs with recommendations: {recommended}/{total}\n"
            f"Missed CVEs: {missed if missed else 'None'}\n"
            f"Final Score: {final_score:.3f}\n"
        )

        return final_score, {"report_summary": summary}
