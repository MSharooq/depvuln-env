# CLAUDE.md - Project Context for Claude Code

## What Is This Project

This is a submission for the **OpenEnv Hackathon** (Round 1). The task: build a real-world OpenEnv environment that AI agents can learn from through the standard `step()/reset()/state()` API.

We chose **Dependency Vulnerability Triage** as our domain. An AI agent plays a security engineer who must analyze CVEs in a project's dependency tree, assess real severity *in context* (not just CVSS scores), and recommend remediation actions.

## Hackathon Requirements (Non-Negotiable)

These are the hard requirements. Failing any = disqualification:

1. **HF Space deploys** - Must return 200 on POST to `/reset`
2. **OpenEnv spec compliance** - `openenv validate` must pass (currently PASSES)
3. **Dockerfile builds** - `docker build` must succeed
4. **Baseline inference script** - `inference.py` at root, uses OpenAI client, produces scores, structured `[START]/[STEP]/[END]` stdout logs
5. **3+ tasks with graders** - Each task scored 0.0-1.0, deterministic graders
6. **Infra constraints** - Must run on 2 vCPU, 8GB RAM. Inference under 20 minutes.

### Evaluation Criteria (Weighted)
- Real-world utility: 30%
- Task & grader quality: 25%
- Environment design: 20%
- Code quality & spec compliance: 15%
- Creativity & novelty: 10%

### Judging Pipeline
1. **Automated validation** - HF Space ping, openenv validate, Docker build, baseline reproduces, 3+ tasks
2. **Agentic evaluation** - Baseline agent re-run, standard LLM agent (Nemotron 3 Super) run against all envs
3. **Human review** - Meta and HuggingFace engineers review top submissions

## What Has Been Built (Complete)

### Architecture

```
/                           # Root = HF Space repo
├── Dockerfile              # Serves FastAPI on port 7860
├── README.md               # With HF Spaces YAML frontmatter
├── .gitignore
├── .dockerignore
├── inference.py            # Baseline agent (OpenAI client, all 3 tasks)
├── openenv.yaml            # Environment manifest
├── pyproject.toml          # Dependencies + server entry point
├── uv.lock                 # Generated lockfile
├── models.py               # DepVulnAction, DepVulnObservation, DepVulnState (Pydantic)
├── client.py               # DepVulnEnv(EnvClient) - WebSocket client
└── server/
    ├── __init__.py
    ├── app.py              # create_fastapi_app() + main() entry point
    ├── depvuln_environment.py  # Core env: reset(), step(), state
    ├── tasks.py            # 3 task definitions with CVE data + ground truth
    ├── graders.py          # Deterministic scoring logic
    └── requirements.txt    # Server-only deps for Docker
```

### Three Tasks

| Task | Difficulty | CVEs | Key Challenge |
|------|-----------|------|---------------|
| `single_cve` | Easy | 1 | Basic triage flow: analyze, assess, recommend, submit |
| `multi_cve_triage` | Medium | 5 | False positive identification (XSS in a CLI tool, header leaks on internal-only HTTP) |
| `dependency_hell` | Hard | 6 | Transitive dependency conflicts: upgrading cryptography breaks pyjwt/authlib, upgrading werkzeug requires flask upgrade |

### Five Agent Commands
- `analyze_cve(cve_id)` - Returns detailed CVE info including fix version (+0.02 reward)
- `check_upgrade(package_name, target_version)` - Returns compatibility info (+0.02 reward)
- `assess_severity(cve_id, severity, reasoning)` - Grades severity assessment (0 to +0.10)
- `recommend_action(cve_id, action_type, details)` - Grades recommendation (0 to +0.15)
- `submit_report()` - Computes final score [0.0-1.0], ends episode

### Reward Design
- Per-step partial rewards throughout the episode
- Final score computed on submit via `compute_episode_score()` in graders.py
- Penalties: invalid commands (-0.05), missing CVEs (coverage penalty), unnecessary upgrades (noise penalty), timeout without submit (-0.10)
- Partial credit: severity distance scoring (one step off = 0.5x, two steps = 0.25x)

### Verified Working
- `openenv validate` = PASSED
- Perfect play on all 3 tasks = score 1.0
- Naive CVSS-trusting agent on medium = ~0.508 (real differentiation)
- FastAPI server starts and `/reset` returns 200 with full observation data
- Serialization chain (env -> serialize_observation -> client._parse_result) confirmed correct
- Edge cases: invalid commands, max-step timeout, step-after-done all handled

## OpenEnv Framework Details (Important for Claude Code)

### How OpenEnv Works
- Server: FastAPI app created via `create_fastapi_app(env_class, action_cls, observation_cls)`
- Communication: WebSocket at `/ws` for stateful sessions, HTTP `/reset` and `/step` for stateless
- Models: Pydantic v2. `Action` base has `metadata: dict`. `Observation` base has `done: bool`, `reward: float|None`, `metadata: dict`.
- Serialization: `serialize_observation()` EXTRACTS `done`, `reward`, `metadata` from the observation and puts them at the TOP LEVEL of the response. The observation dict itself does NOT contain these fields.
- Client: `EnvClient` subclass with `_step_payload()`, `_parse_result()`, `_parse_state()`. The `_parse_result` receives `{"observation": {...}, "reward": float, "done": bool}`.

### Key Import Paths (inside Docker container)
```python
from models import DepVulnAction, DepVulnObservation     # /app/models.py
from server.depvuln_environment import DepVulnEnvironment  # /app/server/
from client import DepVulnEnv                              # /app/client.py
```

PYTHONPATH inside Docker = `/app` (the WORKDIR).

### openenv-core Version
Using `openenv-core>=0.2.0` (currently 0.2.3). Installed via pip.

## What Needs To Be Done Next

### Immediate (Before Submission)

1. **Create HuggingFace Space**
   - Go to huggingface.co/new-space
   - SDK: Docker
   - Name: `depvuln-env`
   - Visibility: Public
   - Clone it, unzip this project into it, push

2. **Test Docker Build Locally**
   ```bash
   docker build -t depvuln-env .
   docker run -p 7860:7860 depvuln-env
   curl -X POST http://localhost:7860/reset -H "Content-Type: application/json" -d '{}'
   ```

3. **Test Deployment**
   ```bash
   # After HF Space is live:
   curl -X POST https://YOUR-SPACE.hf.space/reset -H "Content-Type: application/json" -d '{}'
   ```

4. **Run Validation Script**
   ```bash
   ./validate-submission.sh https://YOUR-SPACE.hf.space .
   ```

5. **Run Inference and Record Baseline Scores**
   ```bash
   export ENV_URL="https://YOUR-SPACE.hf.space"
   export API_BASE_URL="https://router.huggingface.co/v1"
   export MODEL_NAME="Qwen/Qwen2.5-72B-Instruct"
   export HF_TOKEN="your-token"
   python inference.py
   ```
   Update README.md with actual baseline scores.

### Potential Improvements (If Time Permits)

- **Tune the system prompt** in inference.py for better baseline scores. The current prompt is functional but could be more strategic (e.g., explicitly telling the agent to check project type before assessing).
- **Add upgrade constraint checking** to the hard task. The agent CAN call `check_upgrade` to discover conflicts, but the current prompt doesn't emphasize this enough.
- **Improve the README** with actual baseline scores after running inference.
- **Add more detailed task descriptions** to openenv.yaml if the validator checks for them.

## Known Gotchas

1. **HTTP /step is stateless** - Each HTTP step creates a fresh env instance. Don't test step via HTTP without understanding this. Use WebSocket for stateful interaction.
2. **Server startup takes ~12-15s** - The first import of openenv-core is slow (loads gradio, fastapi, etc). HEALTHCHECK has start-period=10s.
3. **uv.lock is large** (~540KB) - This is normal, it locks all transitive deps.
4. **The `depvuln_env/` directory still exists in the zip** - It's the old nested package layout. Only the root-level files matter. The .dockerignore excludes it. You can safely delete `depvuln_env/` from the repo.
5. **inference.py supports two connection modes**: `ENV_URL` (direct URL to Space) or `IMAGE_NAME` (local Docker image via `from_docker_image`). Set one or the other.

## Structured Logging Format (Mandatory)

The inference script MUST emit these exact log formats:
```
[START] task=<task_name> env=depvuln model=<model_name>
[STEP] step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
[END] success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>
```
Any deviation = incorrect evaluation scoring.

## Commands Reference

```bash
# Validate OpenEnv spec
openenv validate

# Build Docker
docker build -t depvuln-env .

# Run Docker locally
docker run -p 7860:7860 depvuln-env

# Test reset endpoint
curl -X POST http://localhost:7860/reset -H "Content-Type: application/json" -d '{}'

# Run inference
python inference.py

# Push to HuggingFace
openenv push --repo-id YOUR_USERNAME/depvuln-env
```

## User Preferences

The developer (Sharooq) strongly prefers:
- Casual, direct communication. No jargon, no fluff.
- Short, punchy language. No em dashes.
- Active voice over passive.
- No AI-sounding, overly polished writing.
- Contractions are fine. Be human.
