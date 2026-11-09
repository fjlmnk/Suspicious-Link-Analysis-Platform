from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base
import app.models # ensure all models are imported and registered on Base.metadata
from app.api import auth, scans, reports, demo
from app.middleware.security import SecurityHeadersMiddleware
from app.middleware.rate_limiter import RateLimiterMiddleware

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield

app = FastAPI(
    title="Suspicious Link Analysis Platform",
    description="Malicious URL and Phishing Detection System with Threat Intelligence Aggregation",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom Middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimiterMiddleware)

# API Routers
app.include_router(auth.router, prefix="/api", tags=["Authentication & Profile"])
app.include_router(scans.router, prefix="/api", tags=["URL Scans"])
app.include_router(reports.router, prefix="/api", tags=["Threat Reports"])
app.include_router(demo.router, prefix="/api", tags=["Demo Scenarios"])

@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "service": "Suspicious Link Analysis Platform",
        "version": "1.0.0"
    }
