from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class SimulationLaunchRequest(BaseModel):
    campaign_name: str = Field(min_length=2, max_length=80)
    target_emails: list[str] = Field(min_length=1, max_length=50)
    template_key: str
    safe_test_mode: bool = True


class SimulationStatusUpdate(BaseModel):
    status: Literal["Sent", "Opened", "Clicked", "Compromised"]


class ThreatAnalysisRequest(BaseModel):
    content: str = Field(min_length=1, max_length=100_000)
