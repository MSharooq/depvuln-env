"""
Inference Script - DepVuln Triage Environment
==============================================
MANDATORY
- Before submitting, ensure the following variables are defined:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.
    IMAGE_NAME     Docker image name (if using from_docker_image)

STDOUT FORMAT
- [START] task=<task_name> env=depvuln model=<model_name>
- [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
- [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>
"""

import asyncio
import json
import os
import re
import textwrap
from typing import Any, Dict, List, Optional

from openai import OpenAI

from models import DepVulnAction
from client import DepVulnEnv

IMAGE_NAME = os.getenv("IMAGE_NAME")
API_KEY = os.getenv("API_KEY") or os.getenv("HF_TOKEN")
API_BASE_URL = os.getenv("API_BASE_URL") or "https://router.huggingface.co/v1"
MODEL_NAME = os.getenv("MODEL_NAME") or "Qwen/Qwen2.5-72B-Instruct"
BENCHMARK = "depvuln"
TEMPERATURE = 0.3
MAX_TOKENS = 800

# Tasks to run
TASKS = ["single_cve", "multi_cve_triage", "dependency_hell"]

SYSTEM_PROMPT = textwrap.dedent("""\
You are a security engineer triaging dependency vulnerabilities.

You interact with an environment via structured JSON commands.
Each turn, respond with EXACTLY ONE JSON object (no markdown, no explanation).

Available commands:

1. Analyze a CVE for details:
   {"command": "analyze_cve", "cve_id": "CVE-XXXX-XXXXX"}

2. Check if upgrading a package is safe:
   {"command": "check_upgrade", "package_name": "pkg", "target_version": "X.Y.Z"}

3. Assess the real severity of a CVE in context:
   {"command": "assess_severity", "cve_id": "CVE-XXXX-XXXXX", "severity": "critical|high|medium|low|none", "reasoning": "why"}

4. Recommend an action for a CVE:
   {"command": "recommend_action", "cve_id": "CVE-XXXX-XXXXX", "action_type": "upgrade|patch|accept_risk|replace", "details": "specifics"}

5. Submit your final triage report:
   {"command": "submit_report"}

Strategy:
- First analyze each CVE to understand the details.
- Consider the PROJECT CONTEXT: what type of project is this? Is it internet-facing or internal? Does the vulnerability apply?
- Assess severity IN CONTEXT (not just the CVSS score).
- A server-side vulnerability in a CLI tool might be a false positive.
- Recommend the right action for each CVE.
- Submit your report when all CVEs are handled.

RESPOND WITH ONLY A JSON OBJECT. No markdown fences, no explanation text.\
""")


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    # Truncate action for readability
    action_short = action[:100].replace("\n", " ")
    print(
        f"[STEP] step={step} action={action_short} reward={reward:.2f} "
        f"done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} "
        f"score={score:.3f} rewards={rewards_str}",
        flush=True,
    )


def format_observation(obs: Any) -> str:
    """Convert observation to a string the LLM can reason about."""
    parts = []

    if obs.project_info:
        parts.append(f"PROJECT: {json.dumps(obs.project_info, indent=2)}")

    if obs.dependencies:
        dep_strs = []
        for d in obs.dependencies:
            dep_strs.append(f"  - {d['name']} {d['version']} ({d.get('purpose', '')})")
        parts.append("DEPENDENCIES:\n" + "\n".join(dep_strs))

    if obs.cves:
        cve_strs = []
        for c in obs.cves:
            cve_strs.append(
                f"  - {c['id']}: {c['package']} (CVSS {c['cvss_score']} "
                f"{c['cvss_severity']}) - {c['summary']}"
            )
        parts.append("CVEs TO TRIAGE:\n" + "\n".join(cve_strs))

    if obs.dependency_tree:
        parts.append(f"DEPENDENCY TREE: {json.dumps(obs.dependency_tree)}")

    if obs.analysis_result:
        parts.append(f"ANALYSIS RESULT:\n{obs.analysis_result}")

    if obs.upgrade_info:
        parts.append(f"UPGRADE CHECK:\n{obs.upgrade_info}")

    if obs.assessment_feedback:
        parts.append(f"ASSESSMENT FEEDBACK: {obs.assessment_feedback}")

    if obs.recommendation_feedback:
        parts.append(f"RECOMMENDATION FEEDBACK: {obs.recommendation_feedback}")

    if obs.report_summary:
        parts.append(f"REPORT SUMMARY:\n{obs.report_summary}")

    if obs.error:
        parts.append(f"ERROR: {obs.error}")

    if obs.step_hint:
        parts.append(f"HINT: {obs.step_hint}")

    if obs.steps_remaining is not None:
        parts.append(f"STEPS REMAINING: {obs.steps_remaining}")

    return "\n\n".join(parts)


def parse_llm_response(text: str) -> Dict[str, Any]:
    """Parse LLM output into an action dict, handling common formatting issues."""
    cleaned = text.strip()

    # Remove markdown code fences if present
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    cleaned = cleaned.strip()

    # Try direct JSON parse
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Try to find JSON object in the text
    match = re.search(r"\{[^{}]*\}", cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    # Fallback: submit report
    return {"command": "submit_report"}


def _validate_env_vars() -> None:
    """Ensure required environment variables are present.

    Exits early with a clear message if critical vars are missing.
    """
    missing = []
    if not API_KEY:
        missing.append("HF_TOKEN or API_KEY")
    if not (IMAGE_NAME or os.getenv("ENV_URL")):
        missing.append("ENV_URL or IMAGE_NAME")

    if missing:
        raise SystemExit(f"Missing required env vars: {', '.join(missing)}")


def _check_env_reachable(env_url: str, timeout: int = 5) -> None:
    """Quickly POST to /reset to ensure the environment is reachable.

    Uses only the standard library so no extra deps are required.
    Raises SystemExit if not reachable.
    """
    try:
        from urllib.request import Request, urlopen

        url = env_url.rstrip("/") + "/reset"
        req = Request(url, data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "getcode", lambda: None)()
            if status is None:
                status = 200
            if status != 200:
                raise RuntimeError(f"Unexpected status code: {status}")
    except Exception as exc:  # pragma: no cover - network check
        raise SystemExit(f"Env not reachable at {env_url}: {exc}")


def get_model_action(
    client: OpenAI,
    observation_text: str,
    history: List[Dict[str, str]],
) -> Dict[str, Any]:
    """Call the LLM and parse its response into an action dict."""
    model = os.environ.get("MODEL_NAME", MODEL_NAME)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(history)
    messages.append({"role": "user", "content": observation_text})

    try:
        completion = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
            stream=False,
        )
        raw = (completion.choices[0].message.content or "").strip()
        action_dict = parse_llm_response(raw)

        # Record in history for context
        history.append({"role": "user", "content": observation_text})
        history.append({"role": "assistant", "content": raw})

        # Keep history manageable (last 10 exchanges)
        if len(history) > 20:
            history[:] = history[-20:]

        return action_dict

    except Exception as exc:
        print(f"[DEBUG] Model request failed: {exc}", flush=True)
        return {"command": "submit_report"}


def dict_to_action(d: Dict[str, Any]) -> DepVulnAction:
    """Convert a parsed dict to a DepVulnAction, handling missing fields."""
    return DepVulnAction(
        command=d.get("command", "submit_report"),
        cve_id=d.get("cve_id"),
        package_name=d.get("package_name"),
        target_version=d.get("target_version"),
        severity=d.get("severity"),
        reasoning=d.get("reasoning"),
        action_type=d.get("action_type"),
        details=d.get("details"),
    )


async def run_task(client: OpenAI, task_name: str) -> float:
    """Run a single task and return the final score."""
    # Prepare bookkeeping and emit START early so failures still produce an END line
    rewards: List[float] = []
    steps_taken = 0
    score = 0.0
    success = False

    log_start(task=task_name, env=BENCHMARK, model=os.environ.get("MODEL_NAME", MODEL_NAME))

    try:
        # Support both Docker image and direct URL connection
        env_url = os.getenv("ENV_URL")

        # Initialize env with reachability check for HTTP mode
        try:
            if env_url:
                _check_env_reachable(env_url)
                env = DepVulnEnv(base_url=env_url)
            elif IMAGE_NAME:
                env = await DepVulnEnv.from_docker_image(IMAGE_NAME)
            else:
                raise RuntimeError("Set either IMAGE_NAME or ENV_URL environment variable")
        except Exception as exc:
            print(f"[DEBUG] Failed to initialize environment for {task_name}: {exc}", flush=True)
            raise

        async with env:
            # Reset the environment (may raise)
            result = await env.reset(task=task_name)
            obs_text = format_observation(result.observation)
            history: List[Dict[str, str]] = []

            max_steps = result.observation.steps_remaining or 20

            for step in range(1, max_steps + 1):
                if result.done:
                    break

                action_dict = get_model_action(client, obs_text, history)
                action = dict_to_action(action_dict)

                # Attempt the step; on failure, log a STEP with error and abort
                try:
                    result = await env.step(action)
                except Exception as exc:
                    error_msg = str(exc)
                    action_str = json.dumps(action_dict, separators=(",", ":"))
                    rewards.append(0.0)
                    steps_taken = step
                    log_step(step=step, action=action_str, reward=0.0, done=True, error=error_msg)
                    score = 0.0
                    success = False
                    break

                obs = result.observation

                reward = result.reward or 0.0
                done = result.done
                error = obs.error if obs.error else None

                rewards.append(reward)
                steps_taken = step

                action_str = json.dumps(action_dict, separators=(",", ":"))
                log_step(step=step, action=action_str, reward=reward, done=done, error=error)

                obs_text = format_observation(obs)

                if done:
                    # The final reward from submit_report IS the score
                    score = max(reward, 0.0)
                    break

            if not result.done:
                score = 0.0

            score = min(max(score, 0.0), 1.0)
            success = score >= 0.1

    except Exception as e:
        print(f"[DEBUG] Task {task_name} error: {e}", flush=True)
        score = 0.0
        success = False

    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)

    return score


async def main() -> None:
    """Run all tasks and report results."""
    client = OpenAI(
        base_url=os.environ.get("API_BASE_URL", "https://router.huggingface.co/v1"),
        api_key=os.environ.get("API_KEY", os.environ.get("HF_TOKEN", "")),
    )

    scores = {}
    for task_name in TASKS:
        score = await run_task(client, task_name)
        scores[task_name] = score

    print("\n" + "=" * 50, flush=True)
    print("FINAL RESULTS", flush=True)
    print("=" * 50, flush=True)
    for task, s in scores.items():
        print(f"  {task}: {s:.3f}", flush=True)
    avg = sum(scores.values()) / len(scores) if scores else 0.0
    print(f"  AVERAGE: {avg:.3f}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
