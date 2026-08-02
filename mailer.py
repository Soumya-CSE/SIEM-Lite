

import os
import smtplib
import socket
from email.mime.text import MIMEText

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")


def _load_dotenv():
    """Tiny .env loader so this project doesn't need an extra pip dependency.
    Existing environment variables always win (so real env config, e.g. in
    production, still overrides a local .env file)."""
    if not os.path.exists(ENV_PATH):
        return
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv()


def is_configured():
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("SMTP_USERNAME") and os.environ.get("SMTP_PASSWORD"))


def send_email(to_addr, subject, body):
    """Send a plain-text email using the server's configured SMTP account.
    Raises ValueError with a human-readable message on any failure."""
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", "587") or "587")
    username = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() not in ("false", "0", "no")
    from_addr = os.environ.get("SMTP_FROM") or username

    if not to_addr:
        raise ValueError("No report email address is set — add one in Settings first.")
    if not host or not username or not password:
        raise ValueError(
            "Email sending isn't set up on this server yet. Whoever's running SIEM Lite needs to "
            "add SMTP details to a .env file - see .env.example for a 5-minute Gmail walkthrough."
        )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr

    try:
        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()
            server.login(username, password)
            server.sendmail(from_addr, [to_addr], msg.as_string())
    except smtplib.SMTPAuthenticationError:
        raise ValueError("The server's SMTP login was rejected — double-check SMTP_USERNAME/SMTP_PASSWORD in .env.")
    except smtplib.SMTPConnectError:
        raise ValueError("Couldn't connect to " + host + ":" + str(port) + " — check SMTP_HOST/SMTP_PORT in .env.")
    except smtplib.SMTPRecipientsRefused:
        raise ValueError("The mail server rejected the recipient address: " + to_addr)
    except smtplib.SMTPException as err:
        raise ValueError("SMTP error: " + str(err))
    except socket.timeout:
        raise ValueError("Connecting to " + host + " timed out — check SMTP_HOST/SMTP_PORT in .env.")
    except socket.gaierror:
        raise ValueError("Couldn't resolve mail server host: " + host)
    except OSError as err:
        raise ValueError("Couldn't reach the mail server: " + str(err))
