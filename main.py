import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

parser = argparse.ArgumentParser(description="Lympha network security orchestrator")
parser.add_argument("--config", default=None, help="path to config file (default: lympha.conf in project root)")
parser.add_argument("--mode", help="test or production (overrides lympha.conf)")
parser.add_argument("--interface", help="network interface to monitor")
parser.add_argument("--eve-path", help="path to Suricata eve.json")
parser.add_argument("--suricata-threshold", type=int, help="Suricata sliding-window threshold")
parser.add_argument("--securebert-threshold", type=int, help="SecureBERT sliding-window threshold")
parser.add_argument("--window", type=int, help="sliding window in minutes")
parser.add_argument("--db", help="SQLite database path")
parser.add_argument("--unblock", help="unblock an IP address and exit")

early_args, _ = parser.parse_known_args()
if early_args.config and load_dotenv:
    load_dotenv(dotenv_path=early_args.config, override=True)

from core.config import DB_PATH, EVE_PATH, INTERFACE, MODE, SECUREBERT_THRESHOLD, SURICATA_THRESHOLD, WINDOW_MINUTES
from core.orchestrator import Orchestrator

parser.set_defaults(
    interface=INTERFACE,
    eve_path=EVE_PATH,
    suricata_threshold=SURICATA_THRESHOLD,
    securebert_threshold=SECUREBERT_THRESHOLD,
    window=WINDOW_MINUTES,
    db=DB_PATH,
    mode=MODE,
)

if __name__ == "__main__":
    args = parser.parse_args()

    if args.unblock:
        orch = Orchestrator(
            interface=args.interface,
            eve_path=args.eve_path,
            suricata_threshold=args.suricata_threshold,
            securebert_threshold=args.securebert_threshold,
            window_minutes=args.window,
            db_path=args.db,
            mode=args.mode,
        )
        orch.db.initialize()
        orch.unblock_ip(args.unblock)
        sys.exit(0)

    Orchestrator(
        interface=args.interface,
        eve_path=args.eve_path,
        suricata_threshold=args.suricata_threshold,
        securebert_threshold=args.securebert_threshold,
        window_minutes=args.window,
        db_path=args.db,
        mode=args.mode,
    ).run()
