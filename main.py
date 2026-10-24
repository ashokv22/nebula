from fastapi import FastAPI

from core.logging_config import configure_logging
from cargo.router import router as cargo_router
from lens.router import router

configure_logging()

app = FastAPI(title="LENS", version="0.1.0")
app.include_router(router)
app.include_router(cargo_router)