import re
import hmac
import logging
import json
import secrets
import uuid
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import get_settings
from .database import Base, engine
from .auth_routes import router as auth_router
from .routes import router
from .team_routes import router as team_router
from .realtime_routes import router as realtime_router
from .voice_routes import router as voice_router
from .tts_routes import router as tts_router
from .public_applications import router as public_applications_router
from .knowledge_routes import router as knowledge_router
from .billing.routes import router as billing_router
from .platform_invitation_routes import router as platform_invitation_router
from .agent_studio_routes import router as agent_studio_router
from .public_activation_security import PublicActivationSecurityMiddleware
from .sse_delivery_trace import SSEDeliveryTraceMiddleware
from .provenance import runtime_provenance_payload

settings=get_settings()
logger = logging.getLogger("orkio.public_applications")
app=FastAPI(title="PatroAI Platform API",docs_url="/docs" if settings.environment!="production" else None)

_allowed_origins = [x.strip() for x in settings.allowed_origins.split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-ORKIO-CSRF", "Idempotency-Key"],
    expose_headers=["X-ORKIO-CSRF", "X-Request-ID"],
)
app.add_middleware(PublicActivationSecurityMiddleware)
app.include_router(auth_router)
app.include_router(router)
app.include_router(team_router)
app.include_router(realtime_router)
app.include_router(voice_router)
app.include_router(tts_router)
app.include_router(public_applications_router)
app.include_router(knowledge_router)
app.include_router(billing_router)
app.include_router(platform_invitation_router)
app.include_router(agent_studio_router)
logger.info("PUBLIC_APPLICATIONS_RUNTIME_LOADED=true cors_origins=%s", _allowed_origins)
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    supplied = request.headers.get("X-Request-ID", "")
    request_id = supplied if _REQUEST_ID_RE.fullmatch(supplied) else str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "microphone=(self)"
    return response

@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    safe_methods = {"GET", "HEAD", "OPTIONS"}
    if request.method.upper() == "OPTIONS" and request.url.path == "/api/public/applications":
        logger.info(
            "PUBLIC_APPLICATIONS_PREFLIGHT origin=%s request_method=%s request_headers=%s",
            request.headers.get("origin", ""),
            request.headers.get("access-control-request-method", ""),
            request.headers.get("access-control-request-headers", ""),
        )
    cookie_token = request.cookies.get("patroai_csrf")
    csrf_token = cookie_token or secrets.token_urlsafe(32)
    if request.method.upper() not in safe_methods and settings.environment in {"staging", "production"}:
        origin = request.headers.get("origin")
        if origin and origin not in _allowed_origins:
            return JSONResponse(status_code=403, content={"detail": "CSRF_ORIGIN_INVALID"})
        supplied = request.headers.get("X-ORKIO-CSRF", "")
        if not cookie_token or not supplied or not hmac.compare_digest(cookie_token, supplied):
            return JSONResponse(status_code=403, content={"detail": "CSRF_TOKEN_INVALID"})
    response = await call_next(request)
    response.headers["X-ORKIO-CSRF"] = csrf_token
    if not cookie_token:
        response.set_cookie(
            key="patroai_csrf",
            value=csrf_token,
            path="/",
            secure=settings.native_session_cookie_secure,
            httponly=False,
            samesite=settings.native_session_cookie_samesite,
        )
    return response


# Last-added middleware is outermost in Starlette's user middleware stack.
# This trace is disabled by default and observes only canonical thread SSE delivery.
app.add_middleware(SSEDeliveryTraceMiddleware)

@app.on_event("startup")
def startup():
    logger.info(
        "RUNTIME_PROVENANCE %s",
        json.dumps(runtime_provenance_payload(settings), sort_keys=True),
    )

    if settings.environment in {"development","test"}:
        Base.metadata.create_all(engine)
