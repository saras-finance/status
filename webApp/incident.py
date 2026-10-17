import argparse
import os
import time
import yaml
from datetime import datetime, timezone

os.chdir(os.path.dirname(os.path.abspath(__file__)))


class IncidentManager:
    def __init__(self, path="incidents.yaml"):
        self.path = path
        self.manual_incidents = self.load_manual_incidents()

    @staticmethod
    def _read_yaml(path):
        if not os.path.exists(path):
            return {"incidents": []}
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data.get("incidents"), list):
            data["incidents"] = []
        return data

    @staticmethod
    def _write_yaml(data, path):
        with open(path, "w") as f:
            yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)

    @staticmethod
    def _format_duration(seconds):
        secs = max(0, int(round(seconds)))
        if secs < 60:
            return f"{max(1, secs)}s"
        mins = secs // 60
        if mins < 60:
            return f"{mins}m" if mins == 1 else f"{mins}mins"
        hrs = mins // 60
        rem_mins = mins % 60
        if hrs < 24:
            return f"{hrs}h {rem_mins}m" if rem_mins else f"{hrs}h"
        days = hrs // 24
        rem_hrs = hrs % 24
        return f"{days}d {rem_hrs}h" if rem_hrs else f"{days}d"

    def load_manual_incidents(self):
        data = self._read_yaml(self.path)
        raw_list = data.get("incidents", [])
        parsed = []
        for idx, inc in enumerate(raw_list):
            if not isinstance(inc, dict):
                continue
            ts = inc.get("time")
            if isinstance(ts, str):
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    ts_val = dt.timestamp()
                except Exception:
                    ts_val = time.time()
            elif isinstance(ts, (int, float)):
                ts_val = float(ts)
            else:
                ts_val = time.time()

            dt_utc = datetime.fromtimestamp(ts_val, tz=timezone.utc)
            default_iso = inc.get("time_iso") or dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
            default_disp = inc.get("time_display") or dt_utc.strftime("%b %d, %Y, %H:%M UTC")

            raw_updates = inc.get("updates")
            updates = []
            if isinstance(raw_updates, list) and raw_updates:
                for u in raw_updates:
                    if isinstance(u, dict):
                        updates.append({
                            "status": str(u.get("status") or inc.get("status") or "Update"),
                            "note": str(u.get("note") or u.get("content") or ""),
                            "time": float(u.get("time") or ts_val),
                            "time_iso": str(u.get("time_iso") or default_iso),
                            "time_display": str(u.get("time_display") or default_disp),
                        })
            else:
                updates.append({
                    "status": str(inc.get("status") or "Investigating"),
                    "note": str(inc.get("content") or ""),
                    "time": ts_val,
                    "time_iso": default_iso,
                    "time_display": default_disp,
                })

            start_t = min((u["time"] for u in updates), default=ts_val)
            latest_t = max((u["time"] for u in updates), default=float(inc.get("updated_time") or ts_val))
            is_resolved = str(inc.get("status") or "").lower() == "resolved"
            resolved_updates = [u["time"] for u in updates if str(u.get("status") or "").lower() == "resolved"]
            resolved_t = max(resolved_updates) if (is_resolved and resolved_updates) else (latest_t if is_resolved else 0)
            end_t = resolved_t if is_resolved else time.time()
            duration_str = self._format_duration(end_t - start_t)

            parsed.append({
                "id": str(inc.get("id") or f"manual-{idx}-{int(ts_val)}"),
                "type": str(inc.get("type") or "incident").lower(),
                "impact": str(inc.get("impact") or "minor").lower(),
                "status": str(inc.get("status") or "Investigating"),
                "service": str(inc.get("service") or "All Services"),
                "group": str(inc.get("group") or "All Groups"),
                "title": str(inc.get("title") or "Service Incident"),
                "content": str(inc.get("content") or ""),
                "created_time": start_t,
                "start_time": start_t,
                "resolved_time": resolved_t,
                "time": latest_t,
                "time_iso": default_iso,
                "time_display": default_disp,
                "duration": duration_str,
                "updates": updates,
            })
        return parsed

    def get_active_override(self, group_name, service_name):
        for inc in self.manual_incidents:
            if str(inc.get("status", "")).lower() == "resolved":
                continue
            inc_group = inc.get("group", "")
            inc_svc = inc.get("service", "")
            if (
                (inc_group == group_name and inc_svc in (service_name, "All Services"))
                or inc_group == "All Groups"
            ):
                return inc
        return None

    def has_incident_on_day(self, day_start, day_end, group_name, service_name):
        return any(
            inc.get("type") == "incident"
            and day_start <= inc.get("created_time", inc.get("time", 0)) < day_end
            and (
                (inc.get("group") == group_name and inc.get("service") in (service_name, "All Services"))
                or inc.get("group") == "All Groups"
            )
            for inc in self.manual_incidents
        )

    def resolve_service_state(self, group_name, service_name, is_up):
        override = self.get_active_override(group_name, service_name)
        state = "operational" if is_up else "offline"
        status_text = "Operational" if is_up else "Outage"
        effective_up = is_up

        if override:
            if override.get("type") == "maintenance":
                state = "maintenance"
                status_text = "Maintenance"
            else:
                if override.get("impact") in ("major", "critical"):
                    state = "offline"
                    status_text = "Outage"
                    effective_up = False
                else:
                    state = "degraded"
                    status_text = "Degraded"
        return effective_up, state, status_text

    def collect_incidents(self, history, meta_lookup):
        events = list(self.manual_incidents)
        for key, hist in history.items():
            if len(hist) < 2:
                continue
            meta = meta_lookup.get(key)
            if not meta:
                continue

            for i in range(1, len(hist)):
                prev, curr = hist[i - 1], hist[i]
                if prev["s"] and not curr["s"]:
                    t_iso = datetime.fromtimestamp(curr["t"], tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    t_disp = datetime.fromtimestamp(curr["t"], tz=timezone.utc).strftime("%b %d, %Y, %H:%M UTC")
                    note = f"Service {meta['name']} in {meta['group']} reported an outage. Status: {curr.get('c') or 'Error'}"
                    events.append({
                        "id": f"auto-{int(curr['t'])}",
                        "type": "incident",
                        "impact": "minor",
                        "status": "Investigating",
                        "service": meta["name"],
                        "group": meta["group"],
                        "title": f"{meta['name']} ({meta['group']}) outage detected",
                        "content": note,
                        "start_time": curr["t"],
                        "resolved_time": 0,
                        "time": curr["t"],
                        "time_iso": t_iso,
                        "time_display": t_disp,
                        "duration": self._format_duration(time.time() - curr["t"]),
                        "updates": [{
                            "status": "Investigating",
                            "note": note,
                            "time": curr["t"],
                            "time_iso": t_iso,
                            "time_display": t_disp,
                        }],
                    })
                elif not prev["s"] and curr["s"]:
                    mins = int((curr["t"] - prev["t"]) / 60) if "t" in prev else 0
                    duration = f" after ~{mins} minutes" if mins > 0 else ""
                    t_iso = datetime.fromtimestamp(curr["t"], tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    t_disp = datetime.fromtimestamp(curr["t"], tz=timezone.utc).strftime("%b %d, %Y, %H:%M UTC")
                    note = f"Service {meta['name']} in {meta['group']} has been restored{duration}."
                    events.append({
                        "id": f"auto-{int(curr['t'])}",
                        "type": "incident",
                        "impact": "minor",
                        "status": "Resolved",
                        "service": meta["name"],
                        "group": meta["group"],
                        "title": f"{meta['name']} ({meta['group']}) issue resolved",
                        "content": note,
                        "start_time": prev.get("t", curr["t"]),
                        "resolved_time": curr["t"],
                        "time": curr["t"],
                        "time_iso": t_iso,
                        "time_display": t_disp,
                        "duration": self._format_duration(curr["t"] - prev["t"]) if "t" in prev else "1m",
                        "updates": [{
                            "status": "Resolved",
                            "note": note,
                            "time": curr["t"],
                            "time_iso": t_iso,
                            "time_display": t_disp,
                        }],
                    })

        events.sort(key=lambda x: x["time"], reverse=True)
        return events[:50]

    @classmethod
    def upsert(
        cls,
        task_id,
        target="",
        inc_type="incident",
        impact="minor",
        status="Investigating",
        title="",
        note="",
        path="incidents.yaml",
    ):
        task_id = (task_id or "").strip()
        if not task_id:
            raise ValueError("Task ID (--task-id / INCIDENT_TASK_ID) is mandatory.")

        target = (target or "").strip()
        inc_type = (inc_type or "incident").strip().lower()
        impact = (impact or "minor").strip().lower()
        status = (status or "Investigating").strip()
        title = (title or "").strip()
        note = (note or "").strip()

        if "::" in target:
            group, service = [part.strip() for part in target.split("::", 1)]
        else:
            group, service = "All Groups", target or "All Services"

        now_ts = round(time.time(), 2)
        now_dt = datetime.fromtimestamp(now_ts, tz=timezone.utc)
        time_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        time_display = now_dt.strftime("%b %d, %Y, %H:%M UTC")

        timeline_entry = {
            "status": status,
            "note": note or f"Status updated to {status}.",
            "time": now_ts,
            "time_iso": time_iso,
            "time_display": time_display,
        }

        data = cls._read_yaml(path)
        incidents = data["incidents"]

        existing = None
        for item in incidents:
            if str(item.get("id", "")).strip().lower() == task_id.lower():
                existing = item
                break

        if existing:
            if not isinstance(existing.get("updates"), list):
                existing["updates"] = []
            existing["updates"].insert(0, timeline_entry)
            existing["status"] = status
            existing["content"] = timeline_entry["note"]
            if impact:
                existing["impact"] = impact
            if title:
                existing["title"] = title
            existing["updated_time"] = now_ts
            existing["time_iso"] = time_iso
            existing["time_display"] = time_display
            print(f"✅ Appended timeline update to Task [{existing['id']}] ({ existing.get('group') } :: { existing.get('service') }) -> {status}")
        else:
            entry = {
                "id": task_id,
                "type": inc_type if inc_type in ("incident", "maintenance") else "incident",
                "impact": impact,
                "status": status,
                "group": group,
                "service": service,
                "title": title or f"{service} ({group}) — {status}",
                "content": timeline_entry["note"],
                "time": now_ts,
                "updated_time": now_ts,
                "time_iso": time_iso,
                "time_display": time_display,
                "updates": [timeline_entry],
            }
            incidents.insert(0, entry)
            print(f"✅ Created new incident for Task [{task_id}] ({group} :: {service}) -> {status}")

        cls._write_yaml(data, path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create or update an incident timeline entry.")
    parser.add_argument("--task-id", default=os.environ.get("INCIDENT_TASK_ID") or os.environ.get("INCIDENT_ID", ""), help="Mandatory Task ID (e.g. TASK-101)")
    parser.add_argument("--target", default=os.environ.get("INCIDENT_TARGET", "Agentic Engine :: LLM Gateway"), help="Group :: Service")
    parser.add_argument("--type", dest="inc_type", default=os.environ.get("INCIDENT_TYPE", "incident"), choices=["incident", "maintenance"])
    parser.add_argument("--impact", default=os.environ.get("INCIDENT_IMPACT", "minor"), choices=["minor", "major", "critical", "none"])
    parser.add_argument("--status", default=os.environ.get("INCIDENT_STATUS", "Investigating"), help="Investigating, Identified, Monitoring, Scheduled, In Progress, Resolved")
    parser.add_argument("--title", default=os.environ.get("INCIDENT_TITLE", ""), help="Incident title (only required on new Task ID)")
    parser.add_argument("--note", default=os.environ.get("INCIDENT_NOTE") or os.environ.get("INCIDENT_CONTENT", ""), help="Timeline note / finding / update")
    args = parser.parse_args()

    IncidentManager.upsert(
        task_id=args.task_id,
        target=args.target,
        inc_type=args.inc_type,
        impact=args.impact,
        status=args.status,
        title=args.title,
        note=args.note,
    )
