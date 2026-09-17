import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from orkio_platform.api.routes import (
    admin,
    agents,
    applications,
    auth,
    chat,
    governance,
    health,
    threads,
    voice,
)
from orkio_platform.config import get_settings
from orkio_platform.domain.errors import DomainError
from orkio_platform.observability.http import (
    request_observability_middleware,
)


def create_app() -> FastAPI:
    settings = get_settings()
    if settings.request_log_enabled:
        logging.basicConfig(level=logging.INFO)
    app = FastAPI(
        title=settings.app_name,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.middleware("http")(
        request_observability_middleware
    )

    @app.exception_handler(DomainError)
    async def domain_error_handler(
        _: Request,
        exc: DomainError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                }
            },
        )

    for router in [
        health.router,
        auth.router,
        agents.router,
        threads.router,
        chat.router,
        voice.router,
        applications.router,
        admin.router,
        governance.router,
    ]:
        app.include_router(router)

    return app


app = create_app()
