from fastapi import APIRouter, Depends
from ..models.schemas import OwaspScanRequest, OwaspScanResult
from ..services.owasp_analyzer import analyze_owasp
from ..core.security import get_current_user
from ..core.logger import log_audit

router = APIRouter()

@router.post("/owasp-scan", response_model=OwaspScanResult)
async def owasp_scan_endpoint(
    request: OwaspScanRequest,
    current_user: dict = Depends(get_current_user)
):
    await log_audit(
        user_id=current_user["id"],
        action=f"OWASP scan on project {request.project_id}",
        ip_address="0.0.0.0",
        user_agent="FastAPI"
    )
    
    result = await analyze_owasp(request.prompt)
    
    return result
