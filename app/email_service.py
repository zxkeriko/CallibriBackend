import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from .auth import settings


def send_verification_email(to_email: str, code: str):
    subject = "Ваш код подтверждения"
    body = f"Ваш код подтверждения: {code}\n\nКод действует 10 минут."

    msg = MIMEMultipart()
    msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            print("SMTP_USER:", settings.SMTP_USER)
            print("SMTP_HOST:", settings.SMTP_HOST)
            print("SMTP_PORT:", settings.SMTP_PORT)
            print("SMTP_PASSWORD length:", len(settings.SMTP_PASSWORD))
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print("EMAIL ERROR:", repr(e))
        raise Exception(f"Failed to send email: {str(e)}")