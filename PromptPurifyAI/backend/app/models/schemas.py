from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime
from uuid import UUID
from pydantic import ConfigDict

# User Schemas
class UserBase(BaseModel):
    email: EmailStr
    role: str = Field(default="viewer")

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: UUID
    created_at: datetime
    class Config:
        from_attributes = True

# Token Schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: Optional[str] = None

# Scan Requests
class ScanRequestBase(BaseModel):
    project_id: UUID
    prompt: str = Field(..., description="The prompt to analyze")

class PromptScanRequest(ScanRequestBase):
    pass

class PoisoningScanRequest(ScanRequestBase):
    training_data_snippet: Optional[str] = None
    model_output: Optional[str] = None

class OwaspScanRequest(ScanRequestBase):
    pass

# Responses
class SeverityEnum(str, Enum):
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"

class PromptScanResult(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    model_config = ConfigDict(use_enum_values=True)
    severity: SeverityEnum
    findings: List[Dict[str, Any]]

class PoisoningScanResult(BaseModel):
    probability: float
    confidence: float
    affected_components: List[str]

class OwaspScanResult(BaseModel):
    compliance_json: Dict[str, Any]
    overall_score: int = Field(ge=0, le=100)

class AgentResult(BaseModel):
    agent_name: str
    findings: Dict[str, Any]
    confidence: float

class MultiAgentScanResult(BaseModel):
    agents: List[AgentResult]
    aggregated_score: int
