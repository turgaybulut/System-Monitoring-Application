import os
from pathlib import Path

# Generate a random secret key if not exists
SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(32).hex())

# Default credentials - change in production
DEFAULT_USERNAME = os.environ.get("MONITOR_USERNAME", "admin")
DEFAULT_PASSWORD = os.environ.get("MONITOR_PASSWORD", "admin")
DEFAULT_PORT = os.environ.get("MONITOR_PORT", 8765)

# Session configuration
SESSION_COOKIE_NAME = "monitor_session"
SESSION_EXPIRY = 3600  # 1 hour in seconds

# Path configurations
BASE_DIR = Path(__file__).parent
CERT_DIR = os.path.join(BASE_DIR.parent, "cert")
