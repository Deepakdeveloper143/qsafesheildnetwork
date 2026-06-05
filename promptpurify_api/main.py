from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from promptpurify_api.models import (
    PromptScanRequest,
    PromptScanResponse,
    PoisoningRequest,
    PoisoningResponse,
    OwaspRequest,
    OwaspResponse,
    AgentAnalysisRequest,
    AgentAnalysisResponse,
)
from promptpurify_api.groq_client import GroqClient
from promptpurify_api.utils import (
    heuristic_prompt_scan,
    heuristic_poisoning_check,
    heuristic_owasp_check,
    run_agents,
)

app = FastAPI(title="PromptPurify API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan-prompt", response_model=PromptScanResponse)
def scan_prompt(req: PromptScanRequest):
    try:
        result = heuristic_prompt_scan(req.prompt)
        return PromptScanResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/detect-poisoning", response_model=PoisoningResponse)
def detect_poisoning(req: PoisoningRequest):
    try:
        result = heuristic_poisoning_check(req.prompt)
        return PoisoningResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/owasp-scan", response_model=OwaspResponse)
def owasp_scan(req: OwaspRequest):
    try:
        result = heuristic_owasp_check(req.prompt)
        return OwaspResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agent-analysis", response_model=AgentAnalysisResponse)
def agent_analysis(req: AgentAnalysisRequest):
    try:
        agents = run_agents(req.prompt, req.options or {})
        return AgentAnalysisResponse(aggregated=agents)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
