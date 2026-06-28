import os
from pathlib import Path

_ENV_PATH = Path(__file__).resolve().parent.parent / "lympha.conf"

try:
    from dotenv import load_dotenv

    load_dotenv(dotenv_path=_ENV_PATH, override=True)
except ImportError:
    pass

MODE = os.getenv("LYMPHA_MODE", "production")
INTERFACE = os.getenv("LYMPHA_INTERFACE", "")
HTTP_PORTS = os.getenv("LYMPHA_HTTP_PORTS", "80")
EVE_PATH = os.getenv("LYMPHA_EVE_PATH", str(Path("suricata/logs/eve.json")))
SURICATA_THRESHOLD = int(os.getenv("LYMPHA_SURICATA_THRESHOLD", "3"))
SECUREBERT_THRESHOLD = int(os.getenv("LYMPHA_SECUREBERT_THRESHOLD", "2"))
WINDOW_MINUTES = int(os.getenv("LYMPHA_WINDOW_MINUTES", "2"))
SECUREBERT_MODEL = os.getenv("LYMPHA_SECUREBERT_MODEL", "ehsanaghaei/SecureBERT")
SECUREBERT_SCORE_THRESHOLD = float(os.getenv("LYMPHA_SECUREBERT_SCORE_THRESHOLD", "0.3"))
DB_PATH = os.getenv("LYMPHA_DB_PATH", "security.db")
