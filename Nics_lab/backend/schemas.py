from typing import Any

from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    ports: list[int] | str
    concurrency: int = Field(default=20, ge=1, le=100)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: list[int] | str) -> list[int] | str:
        if isinstance(value, list) and not value:
            raise ValueError("ports must not be empty")
        return value


class CollectResponse(BaseModel):
    port: int
    status: str
    family: str


class Event(BaseModel):
    type: str
    payload: dict[str, Any]
