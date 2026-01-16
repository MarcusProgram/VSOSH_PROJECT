from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    bot_token: str = Field(default="", alias="TELEGRAM_BOT_TOKEN")
    hmac_secret: str = Field(default="", alias="CONTROL_PLANE_HMAC_SECRET")
    db_path: Path = Path("/data/telegram.sqlite")
    waf_license_key_hash: str = Field(default="", alias="WAF_LICENSE_KEY_HASH")
    max_nonce_age_sec: int = 300
    timestamp_skew_sec: int = 300

    class Config:
        env_file = ".env"
        populate_by_name = True


settings = Settings()
