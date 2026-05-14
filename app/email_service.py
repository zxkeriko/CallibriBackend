import requests

from .auth import settings


def send_verification_email(to_email: str, code: str):
    url = "https://api.brevo.com/v3/smtp/email"

    headers = {
        "accept": "application/json",
        "api-key": settings.SMTP_PASSWORD,
        "content-type": "application/json",
    }

    payload = {
        "sender": {
            "name": settings.SMTP_FROM_NAME,
            "email": settings.SMTP_FROM_EMAIL,
        },
        "to": [
            {
                "email": to_email,
            }
        ],
        "subject": "Ваш код подтверждения",
        "textContent": f"Ваш код подтверждения: {code}\n\nКод действует 10 минут.",
    }

    response = requests.post(
        url,
        json=payload,
        headers=headers,
        timeout=30,
    )

    print("BREVO STATUS:", response.status_code)
    print("BREVO RESPONSE:", response.text)

    if response.status_code >= 400:
        raise Exception(
            f"Brevo API error {response.status_code}: {response.text}"
        )