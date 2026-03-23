from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from .db import Base, engine
from .models import User
from .schemas import RegisterIn, TokenOut, UserOut, VerifyEmailIn, ResendCodeIn, UpdateUserParamsIn
from .auth import (
    get_db,
    hash_password,
    verify_password,
    create_access_token,
    get_user_by_email,
    get_current_user,
    normalize_email,
    normalize_email_basic,
    generate_verification_code,
    settings,
)
from .email_service import send_verification_email
from .admin import setup_admin

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
    # Полная проверка email: формат + нормализация + deliverability
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
            detail=f"Failed to send verification email: {str(e)}"
        )

    return user


@app.post("/auth/verify-email")
def verify_email(data: VerifyEmailIn, db: Session = Depends(get_db)):
    # Тут не нужна DNS-проверка, только нормализация
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
            detail="Failed to send verification email"
        )

    return {"message": "Verification code sent"}


@app.post("/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Для логина только простая нормализация
    email = normalize_email_basic(form.username)
    user = get_user_by_email(db, email)

    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email is not verified"
        )

    token = create_access_token(user.id)
    return TokenOut(access_token=token)

@app.post("/user/update-params")
def update_user_params(data: UpdateUserParamsIn, db: Session = Depends(get_db)):
    email = normalize_email_basic(data.email)
    user = get_user_by_email(db, email)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # обновляем только переданные поля
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


@app.get("/debug/set")
def debug_set(request: Request):
    request.session["token"] = "admin"
    return {"set": True, "session": dict(request.session)}


@app.get("/debug/get")
def debug_get(request: Request):
    return {"session": dict(request.session)}


setup_admin(app)