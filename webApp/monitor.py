import json
import os
import socket
import subprocess
import threading
import time
import urllib3.util.connection as urllib3_cn
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import requests
import yaml

from alerts import AlertDispatcher
from incident import IncidentManager
from renderer import StatusRenderer

os.chdir(os.path.dirname(os.path.abspath(__file__)))

try:
    from curl_cffi import requests as cffi_requests
except ImportError:
    cffi_requests = None

# Force IPv4 to prevent IPv6 route blackhole timeouts on Cloudflare endpoints
urllib3_cn.allowed_gai_family = lambda: socket.AF_INET

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 PulseCheck/2.0",
    "Accept": "application/json, text/html, */*",
}

DEFAULT_API_GROUPS = {
    "Agentic ERP": ["Audit Service", "Data Management", "Projects"],
    "Agentic Engine": [
        "APIs", "Agents", "Choreographer", "Data Handler",
        "LLM Gateway", "Orchestrator", "Secure Vault", "Worker", "Workflows",
    ],
    "Assistant": ["Assistant", "Meeting"],
    "Infra": [
        "Analytics", "Auth Services", "External Queue Management", "IAM Services",
        "Internal Queue Management", "Notification Services", "Queue Service",
        "Settings", "Tenant Services", "Timely Job Services",
    ],
    "Knowledge Repository": [
        "Document Sign", "Documents", "Indexer", "Search Services", "Storage",
    ],
}


def load_yaml(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f)


class Monitor:
    def __init__(self):
        self._lock = threading.Lock()
        self.endpoints_config = load_yaml("endpoints.yaml")
        self.alerts = AlertDispatcher(load_yaml("alerts.yaml"))
        self.incidents = IncidentManager("incidents.yaml")
        self.results = {}
        self.meta_lookup = {}
        self.history_file = "history.json"
        self.history = self.load_history()

    def load_history(self):
        if os.path.exists(self.history_file):
            with open(self.history_file, "r") as f:
                return json.load(f)
        return {}

    def save_history(self):
        history_days = self.endpoints_config.get("history_days", 90)
        cutoff = datetime.now(timezone.utc).timestamp() - (history_days * 24 * 3600)
        for key in list(self.history.keys()):
            self.history[key] = [h for h in self.history[key] if h["t"] > cutoff]
        with open(self.history_file, "w") as f:
            json.dump(self.history, f)
        self.incidents.prune_old_incidents(history_days)

    def fetch_with_retry(self, url, timeout=15, retries=5, retry_interval=2.0):
        class _SimpleResponse:
            def __init__(self, status_code, text):
                self.status_code = status_code
                self.text = text

            def json(self):
                return json.loads(self.text)

        last_err = None
        last_resp = None
        for attempt in range(retries):
            start = time.time()
            if cffi_requests is not None:
                try:
                    resp = cffi_requests.get(
                        url,
                        headers=DEFAULT_HEADERS,
                        impersonate="chrome",
                        timeout=timeout,
                    )
                    elapsed = (time.time() - start) * 1000.0
                    if 200 <= resp.status_code < 400:
                        return resp, elapsed, None
                    last_resp = resp
                except Exception as e:
                    last_err = str(e)

            try:
                start = time.time()
                resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout)
                elapsed = (time.time() - start) * 1000.0
                if 200 <= resp.status_code < 400:
                    return resp, elapsed, None
                last_resp = resp
            except Exception as e:
                last_err = str(e)

            try:
                marker = "__PULSECHECK_META__:"
                cmd = [
                    "curl", "-4", "-sS", "-L",
                    "--max-time", str(timeout),
                    "-A", DEFAULT_HEADERS["User-Agent"],
                    "-H", f"Accept: {DEFAULT_HEADERS['Accept']}",
                    "-w", f"\n{marker}%{{http_code}} %{{time_total}}",
                    url,
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
                if proc.returncode == 0 and marker in proc.stdout:
                    body, meta = proc.stdout.rsplit(f"\n{marker}", 1)
                    parts = meta.strip().split()
                    code = int(parts[0])
                    curl_elapsed = float(parts[1]) * 1000.0
                    c_resp = _SimpleResponse(code, body)
                    if 200 <= code < 400:
                        return c_resp, curl_elapsed, None
                    last_resp = c_resp
            except Exception as ce:
                last_err = last_err or str(ce)

            if attempt < retries - 1:
                fail_status = f"status {last_resp.status_code}" if last_resp else f"error: {last_err}"
                print(f"⚠️ Check attempt {attempt + 1}/{retries} failed for {url} ({fail_status}). Retrying in {retry_interval}s...")
                time.sleep(retry_interval)
        elapsed = (time.time() - start) * 1000.0
        return last_resp, elapsed, last_err

    def record_service_result(self, key, name, group_name, display_url, is_up, elapsed, status_code, error_msg=None, critical=False):
        if not is_up:
            self.alerts.notify(name, group_name, status_code, error_msg, critical)

        safe_elapsed = round(float(elapsed or 0.0), 2)
        now_ts = time.time()
        with self._lock:
            if key not in self.history:
                self.history[key] = []

            self.history[key].append({
                "t": now_ts,
                "s": is_up,
                "r": safe_elapsed,
                "c": status_code,
            })

            self.meta_lookup[key] = {"name": name, "group": group_name, "url": display_url}
            effective_up, state, status_text = self.incidents.resolve_service_state(group_name, name, is_up)

            result = {
                "key": key,
                "name": name,
                "url": display_url,
                "group": group_name,
                "is_up": effective_up,
                "state": state,
                "status_text": status_text,
                "elapsed": safe_elapsed,
                "status": status_code,
                "error": error_msg,
                "history_details": self.history[key][-30:],
                "uptime_bars": self.calculate_bars(key, group_name, name),
                "uptime_pct": self.calculate_uptime(key),
            }

            if group_name not in self.results:
                self.results[group_name] = []
            self.results[group_name].append(result)

    def check_api_health(self):
        api_cfg = self.endpoints_config.get("api_health", {})
        url = api_cfg.get("url", "https://ind-prod.sarasfinance.com/health")
        timeout = api_cfg.get("timeout", 15)
        critical = api_cfg.get("critical", True)

        print(f"🔍 Checking API Health ({url})...")
        resp, elapsed, err = self.fetch_with_retry(url, timeout=timeout, retries=5, retry_interval=2.0)

        is_overall_up = resp is not None and 200 <= resp.status_code < 300
        status_code = resp.status_code if resp is not None else None
        payload = {}
        if is_overall_up:
            try:
                payload = resp.json()
            except Exception:
                payload = {}

        if url not in self.history:
            self.history[url] = []
        self.history[url].append({
            "t": time.time(),
            "s": is_overall_up,
            "r": round(elapsed, 2),
            "c": status_code,
        })

        api_groups = payload.get("groups") if isinstance(payload, dict) else None

        if isinstance(api_groups, dict) and api_groups:
            for group_name in sorted(api_groups.keys(), key=lambda s: s.lower()):
                group_obj = api_groups[group_name] or {}
                services_obj = group_obj.get("services", {})
                for svc_name in sorted(services_obj.keys(), key=lambda s: s.lower()):
                    svc_data = services_obj[svc_name] or {}
                    svc_status = str(svc_data.get("status", "healthy")).lower()
                    svc_is_up = svc_status in ("healthy", "working", "ok", "operational")
                    svc_latency = float(svc_data.get("latencyMs", round(elapsed / 10.0, 2)))
                    svc_key = f"service://{group_name}/{svc_name}"
                    self.record_service_result(
                        key=svc_key,
                        name=svc_name,
                        group_name=group_name,
                        display_url=group_name,
                        is_up=svc_is_up,
                        elapsed=svc_latency,
                        status_code=200 if svc_is_up else 503,
                        error_msg=None if svc_is_up else f"Service reported {svc_status}",
                        critical=critical,
                    )
        else:
            per_svc_latency = round(elapsed / 10.0, 2) if elapsed else 15.0
            for group_name in sorted(DEFAULT_API_GROUPS.keys(), key=lambda s: s.lower()):
                for svc_name in sorted(DEFAULT_API_GROUPS[group_name], key=lambda s: s.lower()):
                    svc_key = f"service://{group_name}/{svc_name}"
                    self.record_service_result(
                        key=svc_key,
                        name=svc_name,
                        group_name=group_name,
                        display_url=group_name,
                        is_up=is_overall_up,
                        elapsed=per_svc_latency,
                        status_code=status_code or (200 if is_overall_up else 503),
                        error_msg=err,
                        critical=critical,
                    )

    def check_endpoint(self, endpoint, group_name):
        name, url = endpoint.get("name"), endpoint.get("url")
        print(f"🔍 Checking {name} ({url})...")
        resp, elapsed, err = self.fetch_with_retry(url, timeout=endpoint.get("timeout", 15), retries=5, retry_interval=2.0)
        status_code = resp.status_code if resp is not None else None
        is_up = resp is not None and 200 <= resp.status_code < 400

        self.record_service_result(
            key=url,
            name=name,
            group_name=group_name,
            display_url=url,
            is_up=is_up,
            elapsed=elapsed,
            status_code=status_code,
            error_msg=err,
            critical=endpoint.get("critical", False),
        )

    def calculate_bars(self, key, group_name=None, service_name=None):
        bars = []
        now = datetime.now(timezone.utc)
        hist = self.history.get(key, [])
        for i in range(89, -1, -1):
            day_dt = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
            day_start = day_dt.timestamp()
            day_end = day_start + 86400
            day_label = day_dt.strftime("%b %d, %Y")
            day_checks = [h for h in hist if day_start <= h["t"] < day_end]

            has_manual_incident = self.incidents.has_incident_on_day(
                day_start, day_end, group_name, service_name
            )

            if not day_checks and not has_manual_incident:
                bars.append({
                    "status": "none",
                    "date": day_label,
                    "label": f"{day_label}: No data recorded",
                    "detail": day_label,
                })
                continue

            total_checks = len(day_checks)
            up_checks = len([h for h in day_checks if h.get("s", False)])
            day_pct = round((up_checks / total_checks * 100.0), 1) if total_checks > 0 else 100.0

            if has_manual_incident:
                status = "down" if day_pct < 90.0 else "degraded"
                label = f"{day_label}: Incident reported ({day_pct}% operational)"
            elif day_pct == 100.0:
                status = "up"
                label = f"{day_label}: No incidents (100% Operational)"
            elif day_pct >= 90.0:
                status = "degraded"
                label = f"{day_label}: Partial degradation ({day_pct}% operational)"
            else:
                status = "down"
                label = f"{day_label}: Major outage ({day_pct}% operational)"

            bars.append({
                "status": status,
                "date": day_label,
                "label": label,
                "detail": f"{day_label} • {day_pct}% operational" if total_checks > 0 else day_label,
            })
        return bars

    def calculate_uptime(self, key):
        hist = self.history.get(key, [])
        if not hist:
            return 100.0
        ups = len([h for h in hist if h["s"]])
        return round((ups / len(hist)) * 100.0, 2)

    def run(self):
        self.check_api_health()

        groups = self.endpoints_config.get("groups", [])
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for group in groups:
                g_name = group.get("name")
                for ep in group.get("endpoints", []):
                    futures.append(executor.submit(self.check_endpoint, ep, g_name))
            for fut in futures:
                fut.result()

        self.save_history()
        events = self.incidents.collect_incidents(self.history, self.meta_lookup)
        StatusRenderer.generate_status_page(self.results, events)
        StatusRenderer.generate_rss(events)


if __name__ == "__main__":
    Monitor().run()
