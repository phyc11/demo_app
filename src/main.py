"""FastAPI application entry point."""

from fastapi import FastAPI

from src.api.v1.router import router as api_v1_router


app = FastAPI()
app.include_router(api_v1_router)
