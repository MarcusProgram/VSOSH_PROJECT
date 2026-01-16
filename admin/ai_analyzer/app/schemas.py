from pydantic import BaseModel


class AnalyzeRequest(BaseModel):
    method: str
    path: str
    query: str
    body: str | None = None
    content_type: str | None = None


class AnalyzeResponse(BaseModel):
    label: str
    confidence: float
    recommended_action: str
    explanation: str
    suspected_param: str | None = None
