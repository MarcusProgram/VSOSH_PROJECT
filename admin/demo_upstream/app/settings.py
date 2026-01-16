from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    insecure_demo: bool = True
    db_path: str = "/tmp/demo.db"

    class Config:
        env_prefix = ""
        case_sensitive = False
        env_file = ".env"


settings = Settings()
