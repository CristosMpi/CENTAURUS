from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class AudioClassifyRequest(BaseModel):
    sample_rate: int = Field(ge=8000, le=192000)
    samples: List[float] = Field(min_length=256, max_length=400000)


class AudioClassifyResponse(BaseModel):
    label: str
    confidence: float
    probabilities: dict[str, float]
