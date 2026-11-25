from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from api.pentest_routes import router as pentest_router
from api.routes import router as api_router
from config import get_settings
from database import init_db
from scheduler import start_scheduler, stop_scheduler

FRONTEND_INDEX = Path(__file__).resolve().parent / "frontend" / "index.html"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    start_scheduler()
    try:
        yield
    finally:
        stop_scheduler()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        description="Defensive external attack-surface monitor for verified small-business domains.",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.include_router(api_router)
    app.include_router(pentest_router)

    @app.get("/", include_in_schema=False)
    def serve_dashboard() -> FileResponse:
        return FileResponse(FRONTEND_INDEX)

    return app


app = create_app()
