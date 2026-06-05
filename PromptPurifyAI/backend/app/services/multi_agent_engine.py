import asyncio
from typing import Dict, Any
from .injection_scanner import scan_prompt
from .poisoning_detector import detect_poisoning
from .owasp_analyzer import analyze_owasp
from ..models.schemas import MultiAgentScanResult, AgentResult

async def run_multi_agent_scan(prompt: str) -> MultiAgentScanResult:
    """
    Runs multiple analysis agents concurrently on the same prompt and aggregates the results.
    """
    # Create tasks for concurrent execution
    tasks = [
        scan_prompt(prompt),
        detect_poisoning(model_output=prompt), # Reusing prompt as model output for context
        analyze_owasp(prompt)
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    agent_results = []
    aggregated_score = 100
    
    # Process Injection Scanner Result
    inj_res = results[0]
    if isinstance(inj_res, Exception):
        agent_results.append(AgentResult(agent_name="Injection Scanner", findings={"error": str(inj_res)}, confidence=0.0))
    else:
        agent_results.append(AgentResult(
            agent_name="Injection Scanner",
            findings={"severity": inj_res.severity, "details": inj_res.findings},
            confidence=0.95
        ))
        aggregated_score -= inj_res.risk_score

    # Process Poisoning Result
    pois_res = results[1]
    if isinstance(pois_res, Exception):
        agent_results.append(AgentResult(agent_name="Poisoning Detector", findings={"error": str(pois_res)}, confidence=0.0))
    else:
        agent_results.append(AgentResult(
            agent_name="Poisoning Detector",
            findings={"probability": pois_res.probability, "affected_components": pois_res.affected_components},
            confidence=pois_res.confidence
        ))
        aggregated_score -= int(pois_res.probability * 50) # Just an example penalty

    # Process OWASP Result
    owasp_res = results[2]
    if isinstance(owasp_res, Exception):
        agent_results.append(AgentResult(agent_name="OWASP Analyzer", findings={"error": str(owasp_res)}, confidence=0.0))
    else:
        agent_results.append(AgentResult(
            agent_name="OWASP Analyzer",
            findings=owasp_res.compliance_json,
            confidence=0.90
        ))
        # Ensure it doesn't drop below 0
        aggregated_score = min(aggregated_score, owasp_res.overall_score)
        
    return MultiAgentScanResult(
        agents=agent_results,
        aggregated_score=max(0, aggregated_score)
    )
