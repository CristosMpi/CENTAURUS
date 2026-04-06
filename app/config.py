from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "CENTAURUS AI"
    app_version: str = "0.1.0"
    high_risk_threshold: float = 0.75
    medium_risk_threshold: float = 0.4


settings = Settings()
