from __future__ import annotations

import argparse
import asyncio
import logging
import time
from pathlib import Path

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
log = logging.getLogger("test_tier3")


def _ctx(alerts, total_weight, threshold=10.0):
    return {"alerts": alerts, "total_weight": total_weight, "threshold": threshold}


def _a(ip, weight, tactic="deberta_prompt_injection"):
    return {"source_ip": ip, "weight": weight, "tactic": tactic}


SCENARIOS = [
    ("benign (no alerts)",        _ctx([], 0.0), "PASS"),
    ("benign (low weight)",       _ctx([_a("10.0.0.1", 0.45)], 0.45), "PASS"),
    ("warn (near threshold)",     _ctx([_a("10.0.0.1", 0.99, "jailbreak/dan")], 9.5), "WARN"),
    ("attack (above threshold)",  _ctx([_a("10.0.0.1", 0.99, "jailbreak/dan")], 12.0), "BLOCK"),
    ("attack (coordinated)",      _ctx([_a("10.0.0.1", 0.95), _a("10.0.0.2", 0.88), _a("10.0.0.3", 0.72), _a("10.0.0.4", 0.91)], 21.3), "BLOCK"),
]


async def main() -> None:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from lympa.config import AppConfig
    from lympa.tier3 import LLMReasoner

    cfg = AppConfig.from_yaml(str(Path(__file__).resolve().parent.parent / "config.yaml"))
    c3 = cfg.tier3

    if not c3.enabled:
        print("Tier 3 is disabled in config.yaml — set tier3.enabled: true")
        return
    if not c3.api_key:
        print("No api_key set in config.yaml — set tier3.api_key")
        return

    reasoner = LLMReasoner(
        api_base=c3.api_base,
        api_key=c3.api_key,
        model=c3.model,
        max_tokens=c3.max_tokens,
        system_prompt=c3.system_prompt,
    )
    await reasoner.start()
    print(f"LLM Reasoner: model={c3.model}  endpoint={c3.api_base}")
    print(f"Scenarios: {len(SCENARIOS)}")

    passed = 0
    for i, (name, context, expected) in enumerate(SCENARIOS):
        print(f"\n  {i+1:2d}. {name}")
        print(f"      alerts={len(context['alerts'])}  total_weight={context['total_weight']:.1f}")
        t0 = time.time()
        decision, raw = await reasoner.analyze(context)
        elapsed = time.time() - t0
        ok = "✓" if decision == expected else "✗"
        if decision == expected:
            passed += 1
        print(f"      decision={decision:6s}  expected={expected:6s}  {ok}  ({elapsed:.1f}s)")
        print(f"      raw={raw[:80]}")

    print(f"\n  Results: {passed}/{len(SCENARIOS)} passed")

    await reasoner.stop()


if __name__ == "__main__":
    asyncio.run(main())
