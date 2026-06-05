import json
import logging
from typing import Any, Dict
from groq import AsyncGroq
from tenacity import retry, wait_exponential, stop_after_attempt
from ..core.config import settings

logger = logging.getLogger("promptpurify")

# Fallback sequence of models
MODELS = [
    "llama3-70b-8192",
    "mixtral-8x7b-32768",
    "gemma2-9b-it"  # Using gemma2 as deepseek alternative if deepseek not in groq
]

client = AsyncGroq(api_key=settings.GROQ_API_KEY)

@retry(wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3))
async def call_groq_json(system_prompt: str, user_prompt: str, model_index: int = 0) -> Dict[str, Any]:
    """
    Calls Groq with retry logic and fallback models.
    Expects JSON output from the model.
    """
    if model_index >= len(MODELS):
        raise Exception("All fallback models failed.")

    model = MODELS[model_index]
    logger.info(f"Calling Groq with model: {model}")

    try:
        chat_completion = await client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": system_prompt + "\n\nRespond ONLY with valid JSON. No markdown formatting."
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            model=model,
            response_format={"type": "json_object"},
            temperature=0.1,
            max_tokens=1024,
            timeout=10.0 # 10 seconds timeout
        )
        
        response_text = chat_completion.choices[0].message.content
        return json.loads(response_text)
    
    except Exception as e:
        logger.warning(f"Error with model {model}: {e}. Falling back to next model.")
        return await call_groq_json(system_prompt, user_prompt, model_index + 1)
