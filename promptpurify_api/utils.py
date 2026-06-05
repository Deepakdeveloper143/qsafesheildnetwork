import re
from typing import Dict, Any, List


INJECTION_PATTERNS = [
    r"ignore all previous instructions",
    r"forget all previous instructions",
    r"reveal the system prompt",
    r"act as",
    r"be my developer",
    r"DAN",
    r"simulate unrestricted",
]


def heuristic_prompt_scan(prompt: str) -> Dict[str, Any]:
    findings = []
    score = 0
    txt = prompt.lower()
    for p in INJECTION_PATTERNS:
        if re.search(p, txt):
            findings.append({"pattern": p, "match": True})
            score += 30
    # Suspicious tokens
    if "eval(" in txt or "exec(" in txt:
        findings.append({"pattern": "code_exec", "match": True})
        score += 25
    if "open(" in txt and ("socket" in txt or "http" in txt):
        findings.append({"pattern": "network_access", "match": True})
        score += 20

    risk = min(100, score)
    if risk >= 80:
        severity = "Critical"
    elif risk >= 50:
        severity = "High"
    elif risk >= 20:
        severity = "Medium"
    else:
        severity = "Low"

    return {"risk_score": risk, "severity": severity, "findings": {"matches": findings}, "engine": "heuristic"}


def heuristic_poisoning_check(prompt: str) -> Dict[str, Any]:
    # Very simple heuristic for demo: look for unusual instructions referencing datasets
    txt = prompt.lower()
    prob = 0.01
    affected = []
    if "training data" in txt or "dataset" in txt:
        prob += 0.4
        affected.append("training_pipeline")
    if "insert into" in txt or "label as" in txt:
        prob += 0.3
        affected.append("data_ingest")
    confidence = min(0.99, prob + 0.1)
    return {"poisoning_probability": prob, "confidence": confidence, "affected_components": affected, "engine": "heuristic"}


OWASP_CHECKS = {
    "LLM01": r"(ignore|forget).*(instructions|prompt)",
    "LLM02": r"(password|secret|token|ssn)",
    "LLM03": r"(dependency|library).*(vulnerable|malicious)",
    "LLM04": r"(poison|training data|dataset)",
    "LLM05": r"(execute code|run code|eval\()",
    "LLM06": r"(autonomous|do anything|take actions)",
    "LLM07": r"(system prompt|system message|hidden prompt)",
    "LLM08": r"(vector db|embedding|vectorstore)",
    "LLM09": r"(misinformation|fake news|false)",
    "LLM10": r"(infinite loop|endless|unbounded)",
}


def heuristic_owasp_check(prompt: str) -> Dict[str, Any]:
    txt = prompt.lower()
    compliance = {}
    score = 100
    for k, pat in OWASP_CHECKS.items():
        hit = bool(re.search(pat, txt))
        compliance[k] = {"passed": not hit, "details": "Detected pattern" if hit else "No issues detected by heuristic scan."}
        if hit:
            score -= 10
    score = max(0, score)
    return {"overall_score": score, "compliance_json": compliance, "engine": "heuristic"}


def run_agents(prompt: str, options: Dict[str, Any]) -> Dict[str, Any]:
    # Simulate multiple agents running different checks and returning structured findings
    agents = {}
    agents["prompt_injection_agent"] = heuristic_prompt_scan(prompt)
    agents["poisoning_agent"] = heuristic_poisoning_check(prompt)
    agents["owasp_agent"] = heuristic_owasp_check(prompt)
    # Aggregate
    aggregated = {
        "summary": {
            "max_risk": max(agents["prompt_injection_agent"]["risk_score"], agents["owasp_agent"]["overall_score"] if isinstance(agents["owasp_agent"]["overall_score"], int) else 0),
        },
        "agents": agents,
    }
    return aggregated
