# Copyright (c) 2026. All rights reserved.
# DepVuln Triage Environment - FastAPI Application

from openenv.core.env_server.http_server import create_fastapi_app

from models import DepVulnAction, DepVulnObservation
from server.depvuln_environment import DepVulnEnvironment

app = create_fastapi_app(
    env=DepVulnEnvironment,
    action_cls=DepVulnAction,
    observation_cls=DepVulnObservation,
)


def main():
    """Entry point for running the server directly."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()
