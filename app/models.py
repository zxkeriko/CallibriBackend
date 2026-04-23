from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)

    sex = Column(String, nullable=True)
    age = Column(Integer, nullable=True)
    height_cm = Column(Integer, nullable=True)
    weight_kg = Column(Integer, nullable=True)

    is_verified = Column(Boolean, default=False, nullable=False)
    verification_code = Column(String, nullable=True)
    verification_expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    pulse_sessions = relationship(
        "PulseSession",
        back_populates="user",
        cascade="all, delete-orphan",
    )


class PulseSession(Base):
    __tablename__ = "pulse_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    title = Column(String, nullable=True)
    activity_type = Column(String, nullable=True)
    notes = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=False, index=True)
    ended_at = Column(DateTime, nullable=True)

    avg_bpm = Column(Float, nullable=True)
    min_bpm = Column(Integer, nullable=True)
    max_bpm = Column(Integer, nullable=True)
    sample_count = Column(Integer, nullable=False, default=0)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="pulse_sessions")
    samples = relationship(
        "PulseSample",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="PulseSample.measured_at",
    )


class PulseSample(Base):
    __tablename__ = "pulse_samples"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(
        Integer,
        ForeignKey("pulse_sessions.id"),
        nullable=False,
        index=True,
    )

    measured_at = Column(DateTime, nullable=False, index=True)
    bpm = Column(Integer, nullable=False)
    signal_quality = Column(Integer, nullable=True)

    session = relationship("PulseSession", back_populates="samples")