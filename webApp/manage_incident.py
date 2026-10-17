import os
import time
import yaml
from datetime import datetime, timezone


def load_incidents(path="incidents.yaml"):
    if not os.path.exists(path):
        return {"incidents": []}
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data.get("incidents"), list):
        data["incidents"] = []
    return data


def save_incidents(data, path="incidents.yaml"):
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)


def upsert_incident_from_env(path="incidents.yaml"):
    target = os.environ.get("INCIDENT_TARGET", "").strip()
    inc_type = os.environ.get("INCIDENT_TYPE", "incident").strip().lower()
    impact = os.environ.get("INCIDENT_IMPACT", "minor").strip().lower()
    status = os.environ.get("INCIDENT_STATUS", "Investigating").strip()
    title = os.environ.get("INCIDENT_TITLE", "").strip()
    content = os.environ.get("INCIDENT_CONTENT", "").strip()
    incident_id = os.environ.get("INCIDENT_ID", "").strip()

    if "::" in target:
        group, service = [part.strip() for part in target.split("::", 1)]
    else:
        group, service = "All Groups", target or "All Services"

    now_ts = round(time.time(), 2)
    now_dt = datetime.fromtimestamp(now_ts, tz=timezone.utc)
    time_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    time_display = now_dt.strftime("%b %d, %Y, %H:%M UTC")

    data = load_incidents(path)
    incidents = data["incidents"]

    # Check if updating an existing incident by ID or resolving the latest active one for this service
    existing = None
    if incident_id:
        for item in incidents:
            if str(item.get("id")) == incident_id:
                existing = item
                break
    elif status.lower() in ("resolved", "monitoring", "identified"):
        for item in incidents:
            if (
                item.get("group") == group
                and item.get("service") == service
                and str(item.get("status", "")).lower() != "resolved"
            ):
                existing = item
                break

    if existing:
        existing["status"] = status
        if title:
            existing["title"] = title
        if content:
            existing["content"] = content
        if impact:
            existing["impact"] = impact
        existing["updated_time"] = now_ts
        existing["time_iso"] = time_iso
        existing["time_display"] = time_display
        print(f"Updated incident {existing['id']} ({group} :: {service}) -> {status}")
    else:
        new_id = incident_id or f"manual-{int(now_ts)}"
        entry = {
            "id": new_id,
            "type": inc_type if inc_type in ("incident", "maintenance") else "incident",
            "impact": impact,
            "status": status,
            "group": group,
            "service": service,
            "title": title or f"{service} ({group}) {status}",
            "content": content or f"{service} in {group} is currently {status.lower()}.",
            "time": now_ts,
            "time_iso": time_iso,
            "time_display": time_display,
        }
        incidents.insert(0, entry)
        print(f"Created incident {new_id} ({group} :: {service}) -> {status}")

    save_incidents(data, path)


if __name__ == "__main__":
    upsert_incident_from_env()
