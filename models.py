from typing import List, Optional, Literal
from pydantic import BaseModel, Field, field_validator


class MessageScanRequest(BaseModel):
    text: str = Field(
        ...,
        description="The raw text of the internship offer, lottery message, promotion, or suspicious communication.",
        min_length=3,
        max_length=20000,
    )

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 3:
            raise ValueError("Message text must contain at least 3 non-whitespace characters.")
        return cleaned


class UrlScanRequest(BaseModel):
    url: str = Field(
        ...,
        description="The website URL or link to analyze structurally.",
        min_length=3,
        max_length=2048,
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 3:
            raise ValueError("URL must contain at least 3 non-whitespace characters.")
        return cleaned


class Indicator(BaseModel):
    id: str
    category: str
    title: str
    description: str
    severity: Literal["info", "caution", "warning", "high"]
    matched_text: Optional[str] = None


class ScanResult(BaseModel):
    input_type: Literal["message", "url"]
    analyzed_preview: str
    risk_level: Literal["Low Concern", "Needs Verification", "Suspicious"]
    risk_score: int = Field(..., ge=0, le=100)
    summary: str
    indicators: List[Indicator]
    recommended_actions: List[str]
    limitations: List[str]
    analyzed_at: str
    is_definitive_claim: bool = False
