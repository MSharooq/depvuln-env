# Copyright (c) 2026. All rights reserved.
# DepVuln Triage Environment - Models

from typing import Any, Dict, List, Optional

from pydantic import Field

from openenv.core.env_server.types import Action, Observation, State


class DepVulnAction(Action):
    """Agent action for the dependency vulnerability triage environment.

    The agent sends a command with relevant parameters to interact with
    the environment. Commands: analyze_cve, check_upgrade, assess_severity,
    recommend_action, submit_report.
    """

    command: str = Field(
        ...,
        description=(
            "Command to execute: 'analyze_cve', 'check_upgrade', "
            "'assess_severity', 'recommend_action', 'submit_report'"
        ),
    )
    cve_id: Optional[str] = Field(
        default=None, description="CVE identifier (e.g. CVE-2024-1234)"
    )
    package_name: Optional[str] = Field(
        default=None, description="Package name for upgrade checks"
    )
    target_version: Optional[str] = Field(
        default=None, description="Target version for upgrade checks"
    )
    severity: Optional[str] = Field(
        default=None,
        description="Assessed severity: critical, high, medium, low, none",
    )
    reasoning: Optional[str] = Field(
        default=None, description="Agent reasoning for the assessment"
    )
    action_type: Optional[str] = Field(
        default=None,
        description="Recommended action: upgrade, patch, accept_risk, replace",
    )
    details: Optional[str] = Field(
        default=None, description="Additional details for the recommendation"
    )


class DepVulnObservation(Observation):
    """Observation returned from the DepVuln environment after each step.

    Contains project context, CVE data, and feedback on agent actions.
    """

    # Project context (returned on reset and always available)
    project_info: Optional[Dict[str, Any]] = Field(
        default=None, description="Project metadata"
    )
    dependencies: Optional[List[Dict[str, Any]]] = Field(
        default=None, description="List of project dependencies"
    )
    cves: Optional[List[Dict[str, Any]]] = Field(
        default=None, description="Known CVE reports for this project"
    )
    dependency_tree: Optional[Dict[str, List[str]]] = Field(
        default=None, description="Dependency relationships"
    )

    # Step feedback
    analysis_result: Optional[str] = Field(
        default=None, description="Result of analyze_cve command"
    )
    upgrade_info: Optional[str] = Field(
        default=None, description="Result of check_upgrade command"
    )
    assessment_feedback: Optional[str] = Field(
        default=None, description="Feedback on severity assessment"
    )
    recommendation_feedback: Optional[str] = Field(
        default=None, description="Feedback on recommended action"
    )
    report_summary: Optional[str] = Field(
        default=None, description="Final report summary on submit"
    )

    # Guidance
    step_hint: Optional[str] = Field(
        default=None, description="Hint about available commands"
    )
    error: Optional[str] = Field(
        default=None, description="Error message if command failed"
    )
    task_name: Optional[str] = Field(
        default=None, description="Current task identifier"
    )
    steps_remaining: Optional[int] = Field(
        default=None, description="Steps left in this episode"
    )


class DepVulnState(State):
    """Extended state tracking for DepVuln episodes."""

    task_name: str = ""
    assessed_cves: List[str] = Field(default_factory=list)
    recommended_cves: List[str] = Field(default_factory=list)
    cumulative_reward: float = 0.0
    max_steps: int = 20
