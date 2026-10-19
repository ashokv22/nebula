from typing import Literal

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    request_id: str | None = Field(default=None, alias="requestId")
    text: str | None = None
    minutes: int = Field(default=60, ge=1, le=1440)
    force_refresh: bool = Field(default=False, alias="forceRefresh")

    model_config = {"populate_by_name": True, "extra": "forbid"}


class AnalysisEvidence(BaseModel):
    eventIndex: int | None
    description: str


class AnalysisResponse(BaseModel):
    summary: str
    likelyCause: str
    confidence: Literal["high", "medium", "low"]
    evidence: list[AnalysisEvidence]
    suggestedChecks: list[str]
    limitations: list[str]
    model: Literal["openai/gpt-oss-20b"]