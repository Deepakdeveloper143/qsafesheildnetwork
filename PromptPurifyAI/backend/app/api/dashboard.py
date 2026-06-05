from fastapi import APIRouter, Depends
from typing import Dict, Any, List
from ..core.security import get_current_user, require_role
from ..core.logger import log_audit

router = APIRouter()

@router.get("/dashboard")
async def get_dashboard_data(current_user: dict = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Returns aggregated statistics for the dashboard.
    In a real app, this would query Supabase for scan counts, threats, etc.
    """
    return {
        "total_scans": 1542,
        "critical_threats": 34,
        "owasp_coverage_score": 85,
        "recent_trends": [
            {"date": "2024-01-01", "threats": 5},
            {"date": "2024-01-02", "threats": 12},
            {"date": "2024-01-03", "threats": 8}
        ]
    }

@router.get("/reports/{scan_id}")
async def get_report(scan_id: str, current_user: dict = Depends(get_current_user)):
    """
    Returns PDF or CSV report for a specific scan.
    Stub implementation.
    """
    return {"message": f"Report for scan {scan_id} will be downloaded here."}

@router.get("/audit-logs")
async def get_audit_logs(current_user: dict = Depends(require_role(["admin"]))) -> List[Dict[str, Any]]:
    """
    Returns audit logs. Restricted to admins.
    """
    return [
        {"action": "Scanned prompt", "user": "test@example.com", "time": "2024-01-01T10:00:00Z"},
        {"action": "Exported report", "user": "admin@example.com", "time": "2024-01-01T11:00:00Z"}
    ]
