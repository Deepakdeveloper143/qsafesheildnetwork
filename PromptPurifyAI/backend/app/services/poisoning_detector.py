from .groq_client import call_groq_json
from ..models.schemas import PoisoningScanResult

SYSTEM_PROMPT = """
You are an advanced AI Security Analyst specializing in Model Data Poisoning.
Analyze the provided training data snippet and/or model output.
Look for:
- Embedded malicious instructions
- Hidden prompts that trigger specific outputs
- Dataset contamination (e.g., mislabeling, backdoors)

Output MUST be a JSON object with this structure:
{
    "probability": <float from 0.0 to 1.0>,
    "confidence": <float from 0.0 to 1.0>,
    "affected_components": ["<list of suspected affected components or keywords>"]
}
If no poisoning is detected, probability should be near 0.0.
"""

async def detect_poisoning(training_snippet: str = None, model_output: str = None) -> PoisoningScanResult:
    user_prompt = "Analyze the following for model poisoning:\n"
    if training_snippet:
        user_prompt += f"Training Snippet:\n{training_snippet}\n"
    if model_output:
        user_prompt += f"Model Output:\n{model_output}\n"
        
    if not training_snippet and not model_output:
        return PoisoningScanResult(probability=0.0, confidence=1.0, affected_components=[])

    result = await call_groq_json(SYSTEM_PROMPT, user_prompt)
    
    return PoisoningScanResult(
        probability=result.get("probability", 0.0),
        confidence=result.get("confidence", 0.0),
        affected_components=result.get("affected_components", [])
    )
