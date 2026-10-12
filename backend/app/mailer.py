import smtplib
from email.mime.text import MIMEText

from .config import settings


def _send_email(to_email: str, subject: str, body: str, link_for_fallback: str) -> None:
    if not settings.smtp_host:
        # No mail server configured yet - print the link so you can still test the flow end to end.
        print(f"[email] SMTP not configured. Link for {to_email}:\n{link_for_fallback}", flush=True)
        return
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from or settings.smtp_user or "no-reply@localhost"
    msg["To"] = to_email
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as s:
            if settings.smtp_use_tls:
                s.starttls()
            if settings.smtp_user:
                s.login(settings.smtp_user, settings.smtp_password or "")
            s.sendmail(msg["From"], [to_email], msg.as_string())
    except Exception as e:
        print(f"[email] Could not send to {to_email} ({type(e).__name__}: {e}). Link was:\n{link_for_fallback}", flush=True)


def send_verification_email(to_email: str, link: str) -> None:
    subject = "Confirm your GIS Dashboard account"
    body = (
        "Hello,\n\n"
        "Someone (hopefully you) created an account on the GIS Dashboard with this email address.\n\n"
        f"Click this link to confirm it and activate your account:\n{link}\n\n"
        "This link expires in 48 hours. If you didn't request this, you can ignore this email.\n"
    )
    _send_email(to_email, subject, body, link)


def send_password_reset_email(to_email: str, link: str) -> None:
    subject = "Reset your LLA Land Information Dashboard password"
    body = (
        "Hello,\n\n"
        "Someone (hopefully you) requested a password reset for this account.\n\n"
        f"Click this link to choose a new password:\n{link}\n\n"
        "This link expires in 1 hour. If you didn't request this, you can safely ignore this email "
        "and your password will stay the same.\n"
    )
    _send_email(to_email, subject, body, link)
