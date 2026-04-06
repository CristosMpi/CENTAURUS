from pydantic import BaseModel
import os


class Settings(BaseModel):
    app_name: str = "CENTAURUS AI v2"
    app_version: str = "0.2.0"
    high_risk_threshold: float = float(os.getenv("CENTAURUS_HIGH_RISK", "0.75"))
    medium_risk_threshold: float = float(os.getenv("CENTAURUS_MEDIUM_RISK", "0.45"))
    shared_secret: str = os.getenv("CENTAURUS_SHARED_SECRET", "change-me")
    rate_limit_per_minute: int = int(os.getenv("CENTAURUS_RATE_LIMIT_PER_MINUTE", "60"))


settings = Settings()
