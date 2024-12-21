import os
from pathlib import Path

# Default credentials
DEFAULT_USERNAME = os.environ.get("MONITOR_USERNAME", "admin")
DEFAULT_PASSWORD = os.environ.get("MONITOR_PASSWORD", "admin")
DEFAULT_PORT = int(os.environ.get("MONITOR_PORT", 8765))

# Path configurations
BASE_DIR = Path(__file__).parent
CERT_DIR = os.path.join(BASE_DIR.parent, "cert")

# Monitor configuration
LAST_LOGINS_COUNT = 10
SYSTEM_LOG_LINES = 50
