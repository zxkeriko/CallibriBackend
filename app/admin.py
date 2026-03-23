# app/admin.py
import os

from sqladmin import Admin, ModelView
from sqladmin.authentication import AuthenticationBackend
from starlette.requests import Request
from itsdangerous import URLSafeSerializer

from .db import engine
from .models import User


def _serializer() -> URLSafeSerializer:
    # Один секрет для подписи cookie админки
    secret = os.getenv("ADMIN_SECRET", "CHANGE_ME_ADMIN_SECRET")
    return URLSafeSerializer(secret_key=secret, salt="callibri-admin")


class AdminAuth(AuthenticationBackend):
    """
    Надёжная авторизация для SQLAdmin через подписанную cookie admin_token.
    Не зависит от SessionMiddleware => не будет 'слетать' после 302.
    """

    async def login(self, request: Request) -> bool:
        try:
            form = await request.form()
        except Exception as e:
            print("FORM ERROR:", repr(e))
            return False

        username = form.get("username")
        password = form.get("password")

        print("LOGIN DATA:", username, password)

        admin_user = os.getenv("ADMIN_USER", "admin")
        admin_pass = os.getenv("ADMIN_PASS", "admin")

        if username == admin_user and password == admin_pass:
            request.session["admin"] = True
            return True

        return False
    
    async def logout(self, request: Request) -> bool:
        request.state._clear_admin_cookie = True
        return True

    async def authenticate(self, request: Request) -> bool:
        print("AUTH COOKIE:", request.cookies.get("callibri_session"))
        print("AUTH SESSION:", dict(request.session))
        return bool(request.session.get("admin"))


class UserAdmin(ModelView, model=User):
    name = "User"
    name_plural = "Users"

    column_list = [
        User.id,
        User.email,
        User.full_name,
        User.sex,
        User.age,
        User.height_cm,
        User.weight_kg,
    ]
    column_searchable_list = [User.email, User.full_name]


def setup_admin(app):
    auth_backend = AdminAuth(secret_key=os.getenv("ADMIN_SECRET", "CHANGE_ME_ADMIN_SECRET"))
    admin = Admin(app, engine, authentication_backend=auth_backend)
    admin.add_view(UserAdmin)
