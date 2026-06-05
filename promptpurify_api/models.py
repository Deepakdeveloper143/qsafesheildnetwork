from pydantic import BaseModel
from typing import Optional, Dict, Any, List


class PromptScanRequest(BaseModel):
    prompt: str


class PromptScanResponse(BaseModel):
    risk_score: int
    severity: str
    findings: Dict[str, Any]
    engine: str = "heuristic"


class PoisoningRequest(BaseModel):
    prompt: str


class PoisoningResponse(BaseModel):
    poisoning_probability: float
    confidence: float
    affected_components: List[str]
    engine: str = "heuristic"


class OwaspRequest(BaseModel):
    prompt: str


class OwaspResponse(BaseModel):
    overall_score: int
    compliance_json: Dict[str, Any]
    engine: str = "heuristic"


class AgentAnalysisRequest(BaseModel):
    prompt: str
    options: Optional[Dict[str, Any]] = None


class AgentAnalysisResponse(BaseModel):
    aggregated: Dict[str, Any]
