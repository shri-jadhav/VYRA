import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.v1.assessment import router as assessment_router
from backend.app.api.v1.assets import router as assets_router
from backend.app.api.v1.audit import router as audit_router
from backend.app.api.v1.connectors import router as connectors_router
from backend.app.api.v1.controls import router as controls_router
from backend.app.api.v1.findings import router as findings_router
from backend.app.api.v1.health import router as health_router
from backend.app.api.v1.investigation import router as investigation_router
from backend.app.api.v1.plan_gate import router as plan_gate_router
from backend.app.api.v1.remediation import router as remediation_router
from backend.app.api.v1.reports import router as reports_router
from backend.app.api.v1.verification import router as verification_router
from backend.app.core.config import settings
from backend.app.core.database import Base, SessionLocal, engine
from backend.app.models.models import AuditLog

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("vyra.main")

# Initialize SQLite tables
Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing VYRA Security Platform...")
    db = SessionLocal()
    try:
        existing_log = db.query(AuditLog).first()
        if not existing_log:
            db.add(AuditLog(
                actor="vyra-core",
                action="SYSTEM_INITIALIZATION",
                resource="platform",
                status="SUCCESS",
                details="VYRA initialized with SQLite persistence and read-only AWS safety guardrails."
            ))
            db.commit()
    finally:
        db.close()
    logger.info("VYRA Security Platform initialized successfully.")
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=f"{settings.TAGLINE} | Advanced Cloud & Endpoint Security Engineering Platform",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API v1 Routers
app.include_router(health_router, prefix="/api/v1")
app.include_router(assessment_router, prefix="/api/v1")
app.include_router(assets_router, prefix="/api/v1")
app.include_router(controls_router, prefix="/api/v1")
app.include_router(findings_router, prefix="/api/v1")
app.include_router(remediation_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")
app.include_router(investigation_router, prefix="/api/v1")
app.include_router(connectors_router, prefix="/api/v1")
app.include_router(plan_gate_router, prefix="/api/v1")
app.include_router(verification_router, prefix="/api/v1")



@app.get("/")
def root():
    return {
        "platform": settings.APP_NAME,
        "tagline": settings.TAGLINE,
        "version": settings.APP_VERSION,
        "api_docs": "/docs",
        "profile": settings.AWS_PROFILE,
        "status": "OPERATIONAL"
    }
