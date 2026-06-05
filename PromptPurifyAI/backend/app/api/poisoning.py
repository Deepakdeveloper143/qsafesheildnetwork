from fastapi import APIRouter, Depends
from ..models.schemas import PoisoningScanRequest, PoisoningScanResult
from ..services.poisoning_detector import detect_poisoning
from ..core.security import get_current_user
from ..core.logger import log_audit

router = APIRouter()

@router.post("/detect-poisoning", response_model=PoisoningScanResult)
async def detect_poisoning_endpoint(
    request: PoisoningScanRequest,
    current_user: dict = Depends(get_current_user)
):
    await log_audit(
        user_id=current_user["id"],
        action=f"Scanned for poisoning on project {request.project_id}",
        ip_address="0.0.0.0",
        user_agent="FastAPI"
    )
    
    result = await detect_poisoning(
        training_snippet=request.training_data_snippet,
        model_output=request.model_output
    )
    
    return result
