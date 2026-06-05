from fastapi import APIRouter, Depends
from ..models.schemas import PromptScanRequest, PromptScanResult
from ..services.injection_scanner import scan_prompt as service_scan_prompt
from ..core.security import get_current_user
from ..core.logger import log_audit

router = APIRouter()

@router.post("/scan-prompt", response_model=PromptScanResult)
async def scan_prompt_endpoint(
    request: PromptScanRequest,
    current_user: dict = Depends(get_current_user)
):
    await log_audit(
        user_id=current_user["id"],
        action=f"Scanned prompt for project {request.project_id}",
        ip_address="0.0.0.0", # In real app, extract from request
        user_agent="FastAPI"
    )
    
    result = await service_scan_prompt(request.prompt)
    
    # In a real app, save the result to the Supabase database here before returning
    return result
