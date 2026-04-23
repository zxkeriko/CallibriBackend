from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field


class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    full_name: str


class VerifyEmailIn(BaseModel):
    email: EmailStr
    code: str


class ResendCodeIn(BaseModel):
    email: EmailStr


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UpdateUserParamsIn(BaseModel):
    email: EmailStr
    sex: Optional[str] = None
    age: Optional[int] = None
    height_cm: Optional[int] = None
    weight_kg: Optional[int] = None


class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    sex: Optional[str] = None
    age: Optional[int] = None
    height_cm: Optional[int] = None
    weight_kg: Optional[int] = None
    is_verified: bool

    class Config:
        from_attributes = True


class PulseSampleCreate(BaseModel):
    measured_at: datetime
    bpm: int = Field(..., ge=20, le=260)
    signal_quality: Optional[int] = Field(default=None, ge=0, le=100)


class PulseSamplesBulkCreate(BaseModel):
    samples: List[PulseSampleCreate]


class PulseSampleOut(BaseModel):
    id: int
    measured_at: datetime
    bpm: int
    signal_quality: Optional[int] = None

    class Config:
        from_attributes = True


class PulseSessionCreate(BaseModel):
    title: Optional[str] = None
    activity_type: Optional[str] = None
    notes: Optional[str] = None
    started_at: datetime
    ended_at: Optional[datetime] = None


class PulseSessionUpdate(BaseModel):
    title: Optional[str] = None
    activity_type: Optional[str] = None
    notes: Optional[str] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None


class PulseSessionOut(BaseModel):
    id: int
    title: Optional[str] = None
    activity_type: Optional[str] = None
    notes: Optional[str] = None
    started_at: datetime
    ended_at: Optional[datetime] = None
    avg_bpm: Optional[float] = None
    min_bpm: Optional[int] = None
    max_bpm: Optional[int] = None
    sample_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class PulseSessionDetailOut(PulseSessionOut):
    samples: List[PulseSampleOut] = []