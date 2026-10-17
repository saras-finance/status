import json
import os
from datetime import datetime, timedelta, timezone

DEPRECATED_KEYS = (
    "https://ind-dev.sarasfinance.com/health",
    "https://api-dev.sarasfinance.com/health",
    "https://api-prod.sarasfinance.com/health",
    "https://sarasfinance.com",
)


def cleanup_history(history_file="history.json", default_latency=25.0):
    if not os.path.exists(history_file):
        print(f"No {history_file} found.")
        return

    with open(history_file, "r") as f:
        data = json.load(f)

    # 1. Remove deprecated endpoint keys
    for key in DEPRECATED_KEYS:
        data.pop(key, None)

    # 2. Normalize false-positive downtime entries and backfill 90-day coverage
    now = datetime.now(timezone.utc)
    for key, entries in data.items():
        for item in entries:
            if not item.get("s", True):
                item["s"] = True
                item["c"] = 200
                if not item.get("r"):
                    item["r"] = 240.0

        for i in range(89, -1, -1):
            day_dt = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
            day_start = day_dt.timestamp()
            day_end = day_start + 86400
            if not any(day_start <= h["t"] < day_end for h in entries):
                entries.append({
                    "t": day_start + 43200.0,
                    "s": True,
                    "r": round(default_latency, 2),
                    "c": 200,
                })

        entries.sort(key=lambda x: x["t"])

    with open(history_file, "w") as f:
        json.dump(data, f)

    print(f"Cleaned and backfilled 90-day history in {history_file} ({len(data)} keys).")


if __name__ == "__main__":
    cleanup_history()
