# Lympha — AI-Powered Network Security System

Lympha is a multi-tier network security platform that combines traditional signature-based detection (Suricata), NLP-based anomaly detection (SecureBERT), and LLM-driven threat hunting (e.g., Qwen, DeepSeek) into a unified defense system. Traffic is processed in real time: definitive threats are dropped instantly at the firewall, while suspicious but inconclusive activity is batched and analyzed by an LLM to uncover low-and-slow stealth attacks.

## Architecture

```
                         ┌──────────────────┐
                         │   Network Traffic │
                         └────────┬─────────┘
                                  │
                  ┌───────────────┼───────────────┐
                  │               │               │
                  ▼               ▼               │
           ┌──────────┐   ┌─────────────┐        │
           │ Suricata │   │ SecureBERT  │        │
           │ (sign.)  │   │ (anomaly)   │        │
           └────┬─────┘   └──────┬──────┘        │
                │                │                │
                ▼                ▼                │
          ┌──────────────────────────┐            │
          │    Orchestrator (core)   │            │
          │  ┌─ Redis sliding window │            │
          │  └─ threshold logic      │            │
          └──────┬───────────┬───────┘            │
                 │           │                    │
           ┌─────▼──┐  ┌────▼─────┐              │
           │Tier 1  │  │Tier 2    │◄─────────────┘
           │iptables│  │LLM Hunter│
           │drop IP │  │(eval)    │
           └────────┘  └────┬─────┘
                            │
                      ┌─────▼──────┐
                      │  Firewall  │
                      │  (block)   │
                      └────────────┘

```

### Tier 1: Real-Time Active Defense

Suricata (running in Docker) and SecureBERT (local HuggingFace inference) watch all traffic. The moment either sensor triggers a definitive alert — a known malicious signature or an extremely high anomaly score — the orchestrator bypasses the LLM entirely, drops the packet, and updates iptables to block the source IP. Mitigation happens in microseconds.

### Tier 2: Silent Analysis (LLM Threat Hunting)

Unflagged packets from active sessions are logged into a Redis-backed sliding time window. Every few minutes (or when a session ends), the orchestrator bundles "clean-looking" packet metadata into a chronological sequence and sends it to a local LLM (Ollama). The LLM hunts for coordinated low-and-slow patterns that evade signature-based detection. If it flags a threat, a retrospective IP block is issued.

## Project Structure

```
Lympha/
├── docker-compose.yml            # Suricata container service
├── requirements.txt              # Python dependencies
├── security.db                   # SQLite database (auto-generated)
├── config/
│   └── suricata.yaml             # Suricata configuration
├── core/
│   ├── __init__.py
│   ├── orchestrator.py           # Master daemon: tails logs, runs models, triggers blocks
│   ├── database.py               # SQLite setup, schemas, queries
│   ├── firewall.py               # iptables block/unblock logic
│   └── llm_hunter.py             # Ollama client for structured JSON evaluation
├── models/
│   └── securebert_worker.py      # Payload text extraction & SecureBERT classification
├── dashboard/
│   ├── main.py                   # FastAPI server reading security.db
│   ├── templates/
│   │   └── index.html            # Live dashboard UI (WebSockets)
│   └── static/
│       ├── css/
│       └── js/
└── logs/
    └── suricata/
        └── eve.json              # Real-time alert log (mounted from container)
```

## Prerequisites

- Docker & Docker Compose
- Python 3.10+
- [Ollama](https://ollama.ai) with a compatible model (e.g., `qwen2.5-coder`, `deepseek-r1`)
- iptables (Linux) or compatible firewall backend

## Quick Start

```bash
# 1. Clone the repository
git clone <repo-url> && cd Lympha

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Start Suricata container
docker compose up -d

# 4. Run the orchestrator
python core/orchestrator.py
```

The orchestrator will:
- Tail `eve.json` for Suricata alerts
- Run SecureBERT on extracted HTTP/API payloads
- Manage a Redis sliding window for session tracking
- Invoke the LLM for Tier 2 analysis
- Execute iptables blocks when thresholds are crossed
- Persist all events, incidents, and blocks to SQLite

## Configuration

### Suricata

Edit `config/suricata.yaml` to match your network interface and ruleset. The container binds to the host interface via `network_mode: host` and writes `eve.json` to `./logs/suricata/`.

### SQLite

The database is initialized with WAL mode and synchronous=NORMAL for concurrent read/write performance:

```python
conn.execute("PRAGMA journal_mode=WAL;")
conn.execute("PRAGMA synchronous=NORMAL;")
```

### Orchestrator Tuning

- **Sliding window**: Redis TTL (default 120s)
- **Threshold**: Number of alerts from a single IP within `n` minutes before escalation
- **LLM model**: Set via `OLLAMA_MODEL` environment variable

## Components

| Module | Responsibility |
|---|---|
| `core/orchestrator.py` | Central daemon: tails logs, coordinates sensors, manages Redis cache, invokes LLM, executes blocks |
| `core/database.py` | SQLite schema (`SecurityEvents`, `Incidents`, `ActiveBlocks`) and query helpers |
| `core/firewall.py` | `iptables` wrappers for adding/removing IP blocks |
| `core/llm_hunter.py` | Sends packet-history payloads to Ollama and parses structured JSON responses |
| `models/securebert_worker.py` | Text extraction from HTTP/API payloads + SecureBERT classification |
| `dashboard/` | FastAPI + WebSocket dashboard for real-time monitoring |

## Database Schema

- **SecurityEvents** — individual sensor logs (Suricata alerts + SecureBERT scores)
- **Incidents** — correlated attack contexts reviewed by the LLM
- **ActiveBlocks** — blocked IPs, timestamps, and AI-generated justification strings

## License

MIT
