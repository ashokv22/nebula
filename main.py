from fastapi import FastAPI

from lens.router import router

app = FastAPI(title="LENS", version="0.1.0")
app.include_router(router)