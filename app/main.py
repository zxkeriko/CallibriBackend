from datetime import datetime, timedelta

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response

from .admin import setup_admin
from .auth import (
    create_access_token,
    generate_verification_code,
    get_current_user,
    get_db,
    get_user_by_email,
    hash_password,
    normalize_email,
    normalize_email_basic,
    settings,
    verify_password,
)
from .db import Base, engine
from .email_service import send_verification_email
from .models import PulseSample, PulseSession, User
from .schemas import (
    PulseSamplesBulkCreate,
    PulseSampleOut,
    PulseSessionCreate,
    PulseSessionDetailOut,
    PulseSessionOut,
    PulseSessionUpdate,
    RegisterIn,
    ResendCodeIn,
    TokenOut,
    UpdateUserParamsIn,
    UserOut,
    VerifyEmailIn,
)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Callibri Backend")

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET,
    same_site="lax",
    https_only=False,
    session_cookie="callibri_session",
)


class AdminCookieMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        token = getattr(request.state, "_set_admin_cookie", None)

        if token:
            response.set_cookie(
                key="admin_token",
                value=token,
                httponly=True,
                samesite="lax",
                secure=False,
                path="/",
            )

        if getattr(request.state, "_clear_admin_cookie", False):
            response.delete_cookie("admin_token", path="/")

        return response


app.add_middleware(AdminCookieMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # для разработки
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "API is running", "docs": "/docs"}


@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    email = normalize_email(data.email)

    if get_user_by_email(db, email):
        raise HTTPException(status_code=409, detail="Email already registered")

    code = generate_verification_code()
    user = User(
        email=email,
        full_name=data.full_name,
        password_hash=hash_password(data.password),
        is_verified=False,
        verification_code=code,
        verification_expires_at=datetime.utcnow() + timedelta(minutes=10),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    try:
        send_verification_email(user.email, code)
        print("RESEND CODE:", code)
    except Exception as e:
        db.delete(user)
        db.commit()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send verification email: {str(e)}",
        )

    return user


@app.post("/auth/verify-email")
def verify_email(data: VerifyEmailIn, db: Session = Depends(get_db)):
    email = normalize_email_basic(data.email)
    user = get_user_by_email(db, email)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_verified:
        return {"message": "Email already verified"}

    if not user.verification_code or not user.verification_expires_at:
        raise HTTPException(status_code=400, detail="Verification code not found")

    if user.verification_expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Verification code expired")

    if user.verification_code != data.code.strip():
        raise HTTPException(status_code=400, detail="Invalid verification code")

    user.is_verified = True
    user.verification_code = None
    user.verification_expires_at = None
    db.commit()

    return {"message": "Email verified successfully"}


@app.post("/auth/resend-code")
def resend_code(data: ResendCodeIn, db: Session = Depends(get_db)):
    email = normalize_email_basic(data.email)
    user = get_user_by_email(db, email)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_verified:
        return {"message": "Email already verified"}

    code = generate_verification_code()
    user.verification_code = code
    user.verification_expires_at = datetime.utcnow() + timedelta(minutes=10)
    db.commit()

    try:
        send_verification_email(user.email, code)
        print("RESEND CODE:", code)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Failed to send verification email",
        )

    return {"message": "Verification code sent"}


@app.post("/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    email = normalize_email_basic(form.username)
    user = get_user_by_email(db, email)

    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email is not verified",
        )

    token = create_access_token(user.id)
    return TokenOut(access_token=token)


@app.post("/user/update-params")
def update_user_params(data: UpdateUserParamsIn, db: Session = Depends(get_db)):
    email = normalize_email_basic(data.email)
    user = get_user_by_email(db, email)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if data.sex is not None:
        user.sex = data.sex
    if data.age is not None:
        user.age = data.age
    if data.height_cm is not None:
        user.height_cm = data.height_cm
    if data.weight_kg is not None:
        user.weight_kg = data.weight_kg

    db.commit()
    db.refresh(user)
    return {"message": "User updated"}


@app.get("/auth/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


def _recalculate_session_stats(session_obj: PulseSession):
    values = [sample.bpm for sample in session_obj.samples]

    if not values:
        session_obj.sample_count = 0
        session_obj.min_bpm = None
        session_obj.max_bpm = None
        session_obj.avg_bpm = None
        return

    session_obj.sample_count = len(values)
    session_obj.min_bpm = min(values)
    session_obj.max_bpm = max(values)
    session_obj.avg_bpm = round(sum(values) / len(values), 2)


@app.post("/pulse/sessions", response_model=PulseSessionOut, status_code=201)
def create_pulse_session(
    data: PulseSessionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if data.ended_at and data.ended_at < data.started_at:
        raise HTTPException(status_code=400, detail="ended_at cannot be before started_at")

    session_obj = PulseSession(
        user_id=current_user.id,
        title=data.title,
        activity_type=data.activity_type,
        notes=data.notes,
        started_at=data.started_at,
        ended_at=data.ended_at,
    )

    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)
    return session_obj


@app.get("/pulse/sessions", response_model=list[PulseSessionOut])
def list_pulse_sessions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    sessions = (
        db.query(PulseSession)
        .filter(PulseSession.user_id == current_user.id)
        .order_by(PulseSession.started_at.desc())
        .all()
    )
    return sessions


@app.get("/pulse/sessions/{session_id}", response_model=PulseSessionDetailOut)
def get_pulse_session(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session_obj = (
        db.query(PulseSession)
        .filter(
            PulseSession.id == session_id,
            PulseSession.user_id == current_user.id,
        )
        .first()
    )

    if not session_obj:
        raise HTTPException(status_code=404, detail="Pulse session not found")

    return session_obj


@app.patch("/pulse/sessions/{session_id}", response_model=PulseSessionOut)
def update_pulse_session(
    session_id: int,
    data: PulseSessionUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session_obj = (
        db.query(PulseSession)
        .filter(
            PulseSession.id == session_id,
            PulseSession.user_id == current_user.id,
        )
        .first()
    )

    if not session_obj:
        raise HTTPException(status_code=404, detail="Pulse session not found")

    if data.title is not None:
        session_obj.title = data.title
    if data.activity_type is not None:
        session_obj.activity_type = data.activity_type
    if data.notes is not None:
        session_obj.notes = data.notes
    if data.started_at is not None:
        session_obj.started_at = data.started_at
    if data.ended_at is not None:
        session_obj.ended_at = data.ended_at

    if session_obj.ended_at and session_obj.ended_at < session_obj.started_at:
        raise HTTPException(status_code=400, detail="ended_at cannot be before started_at")

    db.commit()
    db.refresh(session_obj)
    return session_obj


@app.post("/pulse/sessions/{session_id}/samples", response_model=list[PulseSampleOut], status_code=201)
def add_pulse_samples(
    session_id: int,
    data: PulseSamplesBulkCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session_obj = (
        db.query(PulseSession)
        .filter(
            PulseSession.id == session_id,
            PulseSession.user_id == current_user.id,
        )
        .first()
    )

    if not session_obj:
        raise HTTPException(status_code=404, detail="Pulse session not found")

    if not data.samples:
        raise HTTPException(status_code=400, detail="Samples list cannot be empty")

    created_samples = []
    for sample in data.samples:
        sample_obj = PulseSample(
            session_id=session_obj.id,
            measured_at=sample.measured_at,
            bpm=sample.bpm,
            signal_quality=sample.signal_quality,
        )
        db.add(sample_obj)
        created_samples.append(sample_obj)

    db.flush()
    db.refresh(session_obj)
    _recalculate_session_stats(session_obj)

    db.commit()

    for sample in created_samples:
        db.refresh(sample)

    return created_samples


@app.get("/pulse/sessions/{session_id}/samples", response_model=list[PulseSampleOut])
def list_pulse_samples(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session_obj = (
        db.query(PulseSession)
        .filter(
            PulseSession.id == session_id,
            PulseSession.user_id == current_user.id,
        )
        .first()
    )

    if not session_obj:
        raise HTTPException(status_code=404, detail="Pulse session not found")

    samples = (
        db.query(PulseSample)
        .join(PulseSession, PulseSample.session_id == PulseSession.id)
        .filter(
            PulseSession.id == session_id,
            PulseSession.user_id == current_user.id,
        )
        .order_by(PulseSample.measured_at.asc())
        .all()
    )

    return samples


@app.delete("/pulse/sessions/{session_id}", status_code=204)
def delete_pulse_session(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session_obj = (
        db.query(PulseSession)
        .filter(
            PulseSession.id == session_id,
            PulseSession.user_id == current_user.id,
        )
        .first()
    )

    if not session_obj:
        raise HTTPException(status_code=404, detail="Pulse session not found")

    db.delete(session_obj)
    db.commit()
    return Response(status_code=204)


@app.get("/debug/set")
def debug_set(request: Request):
    request.session["token"] = "admin"
    return {"set": True, "session": dict(request.session)}


@app.get("/debug/get")
def debug_get(request: Request):
    return {"session": dict(request.session)}


setup_admin(app)