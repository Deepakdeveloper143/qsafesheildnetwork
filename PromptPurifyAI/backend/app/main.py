from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .core.config import settings

# Initialize limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Production-ready AI security platform API."
)

# Add slowapi limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.PROJECT_NAME} API"}

# Example of rate limited route
@app.get("/health")
@limiter.limit("5/minute")
async def health_check(request):
    return {"status": "healthy"}

# Include routers
from .api import scan, poisoning, owasp, agents, dashboard

app.include_router(scan.router, prefix=settings.API_V1_STR, tags=["Scans"])
app.include_router(poisoning.router, prefix=settings.API_V1_STR, tags=["Poisoning"])
app.include_router(owasp.router, prefix=settings.API_V1_STR, tags=["OWASP"])
app.include_router(agents.router, prefix=settings.API_V1_STR, tags=["Agents"])
app.include_router(dashboard.router, prefix=settings.API_V1_STR, tags=["Dashboard & Reports"])
