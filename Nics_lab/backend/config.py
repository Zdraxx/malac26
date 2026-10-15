from pathlib import Path

from pydantic import BaseModel, Field


class Settings(BaseModel):
    database_url: str = "sqlite:///./recon.db"
    loot_dir: Path = Path("loot")
    request_timeout_seconds: float = Field(default=3.0, gt=0)
    max_concurrency: int = Field(default=100, ge=1, le=100)
    max_body_bytes: int = 2_000_000
    crawl_depth: int = Field(default=2, ge=0, le=2)
    behavior_samples: int = Field(default=5, ge=1, le=10)


settings = Settings()

