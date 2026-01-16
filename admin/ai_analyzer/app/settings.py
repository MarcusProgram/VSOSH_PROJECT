from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_path: Path = Path("/data/ml_artifacts/model.joblib")
    train_on_startup: bool = True
    threshold_block: float = 0.6  # Понижен для демонстрации ML
    threshold_rate_limit: float = 0.4
    sample_limit: int = 256

    class Config:
        env_file = ".env"


settings = Settings()
