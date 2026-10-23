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


class LeadEvidence(BaseModel):
    evidenceRef: str
    timestamp: str
    requestId: str | None = None
    username: str | None = None
    severity: str | None = None
    source: Literal["lead_match", "request_timeline"]
    eventCategory: Literal[
        "BUSINESS_ACTION",
        "STAGE_TRANSITION",
        "FAILURE",
        "REWORK",
        "EXTERNAL_API",
        "ACCESS_CHECK",
        "TECHNICAL",
    ]
    matchedAliases: list[str] = Field(default_factory=list)
    raw: str
    message: str
    eventType: Literal["API_REQUEST", "API_RESPONSE", "WEBHOOK_RECEIVED"] | None = None
    payloadOmitted: bool = False
    apiOperation: str | None = None
    httpMethod: str | None = None
    endpointPath: str | None = None
    httpStatus: int | None = None
    durationMs: int | float | None = None
    errorCode: str | None = None


class LeadInvestigationResponse(BaseModel):
    leadId: str
    environment: Literal["uat", "prod"]
    requestedDays: int
    searchedDays: int
    candidateCount: int
    relatedRequestIds: list[str]
    timingsMs: dict[str, float]
    evidence: list[LeadEvidence]
    requestTimelines: list[dict]
    retrieval: dict
    limitations: list[str]


class LeadCheckProposal(BaseModel):
    action: Literal[
        "REQUEST_INVESTIGATION",
        "LEAD_HISTORY",
        "USER_ACTIVITY",
        "EXTERNAL_API_INSPECTION",
        "COMPARE_ATTEMPTS",
    ]
    title: str
    reason: str
    priority: Literal["high", "medium", "low"]
    evidenceRefs: list[str] = Field(min_length=1, max_length=3)

    model_config = {"extra": "forbid"}


class LeadClaim(BaseModel):
    description: str
    evidenceRefs: list[str] = Field(min_length=1, max_length=5)

    model_config = {"extra": "forbid"}


class LeadTimelineClaim(LeadClaim):
    event: str


class LeadRootCause(BaseModel):
    observedFacts: list[LeadClaim]
    possibleCauses: list[LeadClaim]
    confidence: Literal["high", "medium", "low"]

    model_config = {"extra": "forbid"}


class LeadIntelligenceModel(BaseModel):
    narrative: str
    latestObservedActivity: str | None = None
    currentStage: str | None = None
    summaryEvidenceRefs: list[str] = Field(default_factory=list, max_length=5)
    stageEvidenceRefs: list[str] = Field(default_factory=list, max_length=5)
    confidence: Literal["high", "medium", "low"]
    journeyTimeline: list[LeadTimelineClaim]
    findingsAndAnomalies: list[LeadClaim]
    rootCauseAssessment: LeadRootCause
    suggestedChecks: list[LeadCheckProposal] = Field(max_length=3)
    recommendedNextSteps: list[LeadClaim]
    limitations: list[str]
    model: Literal["openai/gpt-oss-20b"]

    model_config = {"extra": "forbid"}


class LeadEvidenceSupport(BaseModel):
    evidenceRef: str
    timestamp: str
    requestId: str | None = None


class LeadSummaryResponse(BaseModel):
    narrative: str
    latestObservedActivity: str | None
    latestActivityEvidence: list[LeadEvidenceSupport]
    currentStage: str | None
    stageEvidence: list[LeadEvidenceSupport]
    confidence: Literal["high", "medium", "low"]


class LeadClaimResponse(BaseModel):
    description: str
    supportingEvidence: list[LeadEvidenceSupport]


class LeadTimelineResponse(LeadClaimResponse):
    event: str


class LeadRootCauseResponse(BaseModel):
    observedFacts: list[LeadClaimResponse]
    possibleCauses: list[LeadClaimResponse]
    confidence: Literal["high", "medium", "low"]


class LeadSuggestedCheckResponse(BaseModel):
    action: Literal[
        "REQUEST_INVESTIGATION",
        "LEAD_HISTORY",
        "USER_ACTIVITY",
        "EXTERNAL_API_INSPECTION",
        "COMPARE_ATTEMPTS",
    ]
    title: str
    reason: str
    priority: Literal["high", "medium", "low"]
    context: dict[str, str]


class LeadIntelligenceResponse(BaseModel):
    leadSummary: LeadSummaryResponse
    journeyTimeline: list[LeadTimelineResponse]
    findingsAndAnomalies: list[LeadClaimResponse]
    rootCauseAssessment: LeadRootCauseResponse
    suggestedChecks: list[LeadSuggestedCheckResponse]
    recommendedNextSteps: list[LeadClaimResponse]
    limitations: list[str]
    model: Literal["openai/gpt-oss-20b"]