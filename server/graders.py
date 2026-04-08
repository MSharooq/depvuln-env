# Copyright (c) 2026. All rights reserved.
# DepVuln Triage Environment - Graders

"""
Deterministic grading logic.
Each grader scores agent performance on a 0.0-1.0 scale.
"""

from typing import Any, Dict, List, Tuple

# Severity distance map for partial credit
SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_distance(assessed: str, correct: str) -> float:
    """Return a similarity score [0, 1] between two severity levels.
    Exact match = 1.0, one step off = 0.5, two steps = 0.25, etc."""
    a = SEVERITY_ORDER.get(assessed.lower(), -1)
    c = SEVERITY_ORDER.get(correct.lower(), -1)
    if a < 0 or c < 0:
        return 0.0
    dist = abs(a - c)
    if dist == 0:
        return 1.0
    elif dist == 1:
        return 0.5
    elif dist == 2:
        return 0.25
    else:
        return 0.0


ACTION_EQUIVALENCE = {
    "upgrade": "upgrade",
    "patch": "patch",
    "accept_risk": "accept_risk",
    "accept": "accept_risk",
    "ignore": "accept_risk",
    "replace": "replace",
    "replace_package": "replace",
}


def normalize_action(action: str) -> str:
    return ACTION_EQUIVALENCE.get(action.lower().strip(), action.lower().strip())


def grade_assessment(
    cve_id: str,
    assessed_severity: str,
    ground_truth: Dict[str, Any],
) -> Tuple[float, str]:
    """Grade a single CVE severity assessment. Returns (reward, explanation)."""
    if cve_id not in ground_truth:
        return 0.0, f"Unknown CVE: {cve_id}"

    truth = ground_truth[cve_id]
    correct = truth["correct_severity"]
    score = severity_distance(assessed_severity, correct)

    # Bonus for correctly identifying false positives
    if truth.get("is_false_positive", False) and assessed_severity.lower() in ("none", "low"):
        score = min(score + 0.2, 1.0)

    if score >= 0.9:
        explanation = f"Correct severity for {cve_id}: {correct}"
    elif score >= 0.4:
        explanation = f"Close for {cve_id}: assessed '{assessed_severity}', correct '{correct}'"
    else:
        explanation = f"Incorrect for {cve_id}: assessed '{assessed_severity}', correct '{correct}'"

    return score, explanation


def grade_recommendation(
    cve_id: str,
    recommended_action: str,
    ground_truth: Dict[str, Any],
) -> Tuple[float, str]:
    """Grade a single CVE action recommendation. Returns (reward, explanation)."""
    if cve_id not in ground_truth:
        return 0.0, f"Unknown CVE: {cve_id}"

    truth = ground_truth[cve_id]
    correct = normalize_action(truth["correct_action"])
    given = normalize_action(recommended_action)

    if given == correct:
        return 1.0, f"Correct action for {cve_id}: {correct}"

    # Partial credit for reasonable alternatives
    if correct == "upgrade" and given == "patch":
        return 0.5, f"Acceptable for {cve_id}: 'patch' when 'upgrade' is ideal"
    if correct == "accept_risk" and given == "upgrade":
        return 0.3, f"Overcautious for {cve_id}: upgrading when risk is acceptable"
    if correct == "upgrade" and given == "accept_risk":
        return 0.0, f"Dangerous for {cve_id}: accepting risk when upgrade is needed"

    return 0.1, f"Wrong action for {cve_id}: '{given}' vs correct '{correct}'"


def compute_episode_score(
    assessments: Dict[str, str],
    recommendations: Dict[str, str],
    ground_truth: Dict[str, Any],
    task_name: str,
) -> Tuple[float, Dict[str, Any]]:
    """Compute final episode score from all assessments and recommendations.

    Returns:
        (score, details) where score is in [0.0, 1.0].
    """
    total_cves = len(ground_truth)
    if total_cves == 0:
        return 0.0, {"error": "No CVEs in ground truth"}

    details = {"per_cve": {}, "coverage_penalty": 0.0}

    # Score each CVE
    cve_scores = []
    for cve_id in ground_truth:
        cve_detail = {}

        # Assessment score (40% of per-CVE score)
        if cve_id in assessments:
            a_score, a_explain = grade_assessment(
                cve_id, assessments[cve_id], ground_truth
            )
            cve_detail["assessment_score"] = a_score
            cve_detail["assessment_explain"] = a_explain
        else:
            a_score = 0.0
            cve_detail["assessment_score"] = 0.0
            cve_detail["assessment_explain"] = f"CVE {cve_id} was not assessed"

        # Recommendation score (60% of per-CVE score)
        if cve_id in recommendations:
            r_score, r_explain = grade_recommendation(
                cve_id, recommendations[cve_id], ground_truth
            )
            cve_detail["recommendation_score"] = r_score
            cve_detail["recommendation_explain"] = r_explain
        else:
            r_score = 0.0
            cve_detail["recommendation_score"] = 0.0
            cve_detail["recommendation_explain"] = f"CVE {cve_id} had no recommendation"

        combined = 0.4 * a_score + 0.6 * r_score
        cve_detail["combined_score"] = combined
        cve_scores.append(combined)
        details["per_cve"][cve_id] = cve_detail

    # Average across all CVEs
    raw_score = sum(cve_scores) / total_cves

    # Coverage penalty: lose points for unaddressed CVEs
    addressed = set(assessments.keys()) | set(recommendations.keys())
    missed = set(ground_truth.keys()) - addressed
    coverage_penalty = len(missed) * 0.05
    details["coverage_penalty"] = coverage_penalty
    details["missed_cves"] = list(missed)

    # Noise penalty: recommendations for non-existent CVEs
    noise_cves = set(recommendations.keys()) - set(ground_truth.keys())
    noise_penalty = len(noise_cves) * 0.03
    details["noise_penalty"] = noise_penalty

    final_score = max(0.0, min(1.0, raw_score - coverage_penalty - noise_penalty))
    details["raw_score"] = raw_score
    details["final_score"] = final_score

    return final_score, details
