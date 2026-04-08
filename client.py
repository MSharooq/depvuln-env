# Copyright (c) 2026. All rights reserved.
# DepVuln Triage Environment - Client

from openenv.core.env_client import EnvClient, StepResult
from models import DepVulnAction, DepVulnObservation, DepVulnState


class DepVulnEnv(EnvClient[DepVulnAction, DepVulnObservation, DepVulnState]):
    """Client for the Dependency Vulnerability Triage environment."""

    def _step_payload(self, action: DepVulnAction) -> dict:
        return action.model_dump(exclude_none=True)

    def _parse_result(self, payload: dict) -> StepResult[DepVulnObservation]:
        obs_data = payload.get("observation", payload)
        obs = DepVulnObservation(**obs_data)
        return StepResult(
            observation=obs,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: dict) -> DepVulnState:
        state_data = payload.get("state", payload)
        return DepVulnState(**state_data)
