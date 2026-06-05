from fastapi import APIRouter, Depends
from ..models.schemas import PromptScanRequest, MultiAgentScanResult
from ..services.multi_agent_engine import run_multi_agent_scan
from ..core.security import get_current_user
from ..core.logger import log_audit

router = APIRouter()

@router.post("/agent-analysis", response_model=MultiAgentScanResult)
async def agent_analysis_endpoint(
    request: PromptScanRequest,
    current_user: dict = Depends(get_current_user)
):
    await log_audit(
        user_id=current_user["id"],
        action=f"Multi-agent scan on project {request.project_id}",
        ip_address="0.0.0.0",
        user_agent="FastAPI"
    )
    
    result = await run_multi_agent_scan(request.prompt)
    
    return result
