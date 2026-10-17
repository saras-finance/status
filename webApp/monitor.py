import yaml
import requests
import socket
import subprocess
import threading
import urllib3.util.connection as urllib3_cn
import time
import os
import json
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from jinja2 import Template
from feedgen.feed import FeedGenerator

try:
    from curl_cffi import requests as cffi_requests
except ImportError:
    cffi_requests = None

# Force IPv4 to prevent IPv6 route blackhole timeouts on Cloudflare endpoints
urllib3_cn.allowed_gai_family = lambda: socket.AF_INET

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 PulseCheck/2.0",
    "Accept": "application/json, text/html, */*"
}

DEFAULT_API_GROUPS = {
    "Agentic ERP": ["Audit Service", "Data Management", "Projects"],
    "Agentic Engine": [
        "APIs", "Agents", "Choreographer", "Data Handler",
        "LLM Gateway", "Orchestrator", "Secure Vault", "Worker", "Workflows"
    ],
    "Assistant": ["Assistant", "Meeting"],
    "Infra": [
        "Analytics", "Auth Services", "External Queue Management", "IAM Services",
        "Internal Queue Management", "Notification Services", "Queue Service",
        "Settings", "Tenant Services", "Timely Job Services"
    ],
    "Knowledge Repository": [
        "Document Sign", "Documents", "Indexer", "Search Services", "Storage"
    ]
}


# --- Configuration Loader ---
def load_yaml(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f)


# --- Alert Providers ---
class AlertProvider:
    def send(self, data, config):
        raise NotImplementedError


class PushoverAlert(AlertProvider):
    def send(self, data, config):
        c = config.get("providers", {}).get("pushover", {})
        if not c.get("enabled"):
            return
        user_key = os.environ.get(c.get("user_key_env"))
        token = os.environ.get(c.get("token_env"))
        if not user_key or not token:
            return
        message = f"🔴 {data['group']} - {data['name']} is DOWN\nStatus: {data['status']}" if data["status"] else f"Error: {data['error']}"
        try:
            requests.post(
                "https://api.pushover.net/1/messages.json",
                data={
                    "token": token,
                    "user": user_key,
                    "message": message,
                    "priority": 1 if data.get("critical") else 0
                },
                timeout=10
            )
        except Exception as e:
            print(f"🚨 Pushover Error: {e}")


class SendGridAlert(AlertProvider):
    def send(self, data, config):
        c = config.get("providers", {}).get("sendgrid", {})
        if not c.get("enabled"):
            return
        api_key = os.environ.get(c.get("api_key_env"))
        if not api_key:
            return
        message = Mail(
            from_email=c.get("from_email"),
            to_emails=c.get("to_email"),
            subject=f"🔴 PulseCheck Alert: {data['name']} is DOWN",
            plain_text_content=f"Service: {data['name']} ({data['group']}) failed.\nTime: {data['timestamp']}"
        )
        try:
            sg = SendGridAPIClient(api_key)
            sg.send(message)
        except Exception as e:
            print(f"🚨 SendGrid Error: {e}")


class WebhookAlert(AlertProvider):
    def send(self, data, config):
        c = config.get("providers", {}).get("webhook", {})
        if not c.get("enabled"):
            return
        url = os.environ.get(c.get("url_env"))
        if not url:
            return
        headers = {
            k: v.replace("${ALERT_WEBHOOK_BEARER_TOKEN}", os.environ.get("ALERT_WEBHOOK_BEARER_TOKEN", ""))
            for k, v in c.get("headers", {}).items()
        }
        payload = {
            k: v.format(**data) if isinstance(v, str) else v
            for k, v in c.get("payload_template", {}).items()
        }
        try:
            requests.request(c.get("method", "POST"), url, headers=headers, json=payload, timeout=10)
        except Exception as e:
            print(f"🚨 Webhook Error: {e}")


# --- Monitoring Core ---
class Monitor:
    def __init__(self):
        self._lock = threading.Lock()
        self.endpoints_config = load_yaml("endpoints.yaml")
        self.alerts_config = load_yaml("alerts.yaml")
        self.incidents_config = load_yaml("incidents.yaml")
        self.manual_incidents = self.load_manual_incidents()
        self.providers = [PushoverAlert(), SendGridAlert(), WebhookAlert()]
        self.results = {}
        self.meta_lookup = {}
        self.history_file = "history.json"
        self.history = self.load_history()

    def load_manual_incidents(self):
        raw_list = (self.incidents_config or {}).get("incidents", [])
        if not isinstance(raw_list, list):
            return []
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
            parsed.append({
                "id": str(inc.get("id") or f"manual-{idx}-{int(ts_val)}"),
                "type": str(inc.get("type") or "incident").lower(),
                "impact": str(inc.get("impact") or "minor").lower(),
                "status": str(inc.get("status") or "Investigating"),
                "service": str(inc.get("service") or "All Services"),
                "group": str(inc.get("group") or "All Groups"),
                "title": str(inc.get("title") or "Service Incident"),
                "content": str(inc.get("content") or ""),
                "time": ts_val,
                "time_iso": inc.get("time_iso") or dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "time_display": inc.get("time_display") or dt_utc.strftime("%b %d, %Y, %H:%M UTC"),
            })
        return parsed

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

    def fetch_with_retry(self, url, timeout=15, retries=3):
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

            # Fallback to system curl (HTTP/2 + native TLS stack) to avoid LibreSSL/JA3 handshake blocks
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
                time.sleep(1.5)
        elapsed = (time.time() - start) * 1000.0
        return last_resp, elapsed, last_err

    def get_active_manual_override(self, group_name, service_name):
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

    def record_service_result(self, key, name, group_name, display_url, is_up, elapsed, status_code, error_msg=None, critical=False):
        if not is_up:
            self.notify(name, group_name, status_code, error_msg, critical)

        safe_elapsed = round(float(elapsed or 0.0), 2)
        now_ts = time.time()
        with self._lock:
            if key not in self.history:
                self.history[key] = []

            self.history[key].append({
                "t": now_ts,
                "s": is_up,
                "r": safe_elapsed,
                "c": status_code
            })

            self.meta_lookup[key] = {"name": name, "group": group_name, "url": display_url}

            override = self.get_active_manual_override(group_name, name)
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
                "uptime_pct": self.calculate_uptime(key)
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
        resp, elapsed, err = self.fetch_with_retry(url, timeout=timeout, retries=3)

        is_overall_up = resp is not None and 200 <= resp.status_code < 300
        status_code = resp.status_code if resp is not None else None
        payload = {}
        if is_overall_up:
            try:
                payload = resp.json()
            except Exception:
                payload = {}

        # Also keep main URL history updated so baseline history stays current
        if url not in self.history:
            self.history[url] = []
        self.history[url].append({
            "t": time.time(),
            "s": is_overall_up,
            "r": round(elapsed, 2),
            "c": status_code
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
                        critical=critical
                    )
        else:
            # Fallback if endpoint still returns legacy {"status": "ok"} before prod deploy
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
                        critical=critical
                    )

    def check_endpoint(self, endpoint, group_name):
        name, url = endpoint.get("name"), endpoint.get("url")
        print(f"🔍 Checking {name} ({url})...")
        resp, elapsed, err = self.fetch_with_retry(url, timeout=endpoint.get("timeout", 15), retries=3)
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
            critical=endpoint.get("critical", False)
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

            has_manual_incident = any(
                inc.get("type") == "incident"
                and day_start <= inc.get("time", 0) < day_end
                and (
                    (inc.get("group") == group_name and inc.get("service") in (service_name, "All Services"))
                    or inc.get("group") == "All Groups"
                )
                for inc in self.manual_incidents
            )

            if has_manual_incident or any(not h["s"] for h in day_checks):
                bars.append({"status": "down", "date": day_label, "label": f"{day_label}: Incident detected"})
            elif not day_checks:
                bars.append({"status": "none", "date": day_label, "label": f"{day_label}: No data recorded"})
            else:
                bars.append({"status": "up", "date": day_label, "label": f"{day_label}: No incidents (100% Operational)"})
        return bars

    def calculate_uptime(self, key):
        hist = self.history.get(key, [])
        if not hist:
            return 100.0
        ups = len([h for h in hist if h["s"]])
        return round((ups / len(hist)) * 100.0, 2)

    def notify(self, name, group, status, error, critical):
        data = {
            "name": name,
            "group": group,
            "status": status,
            "error": error,
            "critical": critical,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        for provider in self.providers:
            provider.send(data, self.alerts_config)

    def collect_incidents(self):
        events = list(self.manual_incidents)
        for key, hist in self.history.items():
            if len(hist) < 2:
                continue
            meta = self.meta_lookup.get(key)
            if not meta:
                continue

            for i in range(1, len(hist)):
                prev, curr = hist[i - 1], hist[i]
                if prev["s"] and not curr["s"]:
                    events.append({
                        "id": f"down-{key}-{curr['t']}",
                        "type": "incident",
                        "impact": "minor",
                        "status": "Investigating",
                        "service": meta["name"],
                        "group": meta["group"],
                        "title": f"{meta['name']} ({meta['group']}) outage detected",
                        "content": f"Service {meta['name']} in {meta['group']} reported an outage. Status: {curr.get('c') or 'Error'}",
                        "time": curr["t"],
                        "time_iso": datetime.fromtimestamp(curr["t"], tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "time_display": datetime.fromtimestamp(curr["t"], tz=timezone.utc).strftime("%b %d, %Y, %H:%M UTC")
                    })
                elif not prev["s"] and curr["s"]:
                    mins = int((curr["t"] - prev["t"]) / 60) if "t" in prev else 0
                    duration = f" after ~{mins} minutes" if mins > 0 else ""
                    events.append({
                        "id": f"up-{key}-{curr['t']}",
                        "type": "incident",
                        "impact": "minor",
                        "status": "Resolved",
                        "service": meta["name"],
                        "group": meta["group"],
                        "title": f"{meta['name']} ({meta['group']}) issue resolved",
                        "content": f"Service {meta['name']} in {meta['group']} has been restored{duration}.",
                        "time": curr["t"],
                        "time_iso": datetime.fromtimestamp(curr["t"], tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "time_display": datetime.fromtimestamp(curr["t"], tz=timezone.utc).strftime("%b %d, %Y, %H:%M UTC")
                    })

        events.sort(key=lambda x: x["time"], reverse=True)
        return events[:50]

    def generate_status_page(self, events):
        sorted_results = {}
        total_services = 0
        operational_services = 0
        degraded_services = 0
        offline_services = 0
        maintenance_services = 0

        for group_name in sorted(self.results.keys(), key=lambda s: s.lower()):
            svcs = sorted(self.results[group_name], key=lambda x: x["name"].lower())
            sorted_results[group_name] = svcs
            for s in svcs:
                total_services += 1
                state = s.get("state", "operational" if s["is_up"] else "offline")
                if state == "maintenance":
                    maintenance_services += 1
                elif state == "degraded":
                    degraded_services += 1
                elif state == "offline":
                    offline_services += 1
                else:
                    operational_services += 1

        summary = {
            "total": total_services,
            "operational": operational_services,
            "degraded": degraded_services,
            "offline": offline_services,
            "maintenance": maintenance_services,
            "all_operational": offline_services == 0 and degraded_services == 0
        }

        now_utc = datetime.now(timezone.utc)
        with open("status_template.html", "r") as f:
            template = Template(f.read())

        html = template.render(
            results=sorted_results,
            summary=summary,
            incidents=events,
            last_updated=now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            last_updated_iso=now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        with open("../index.html", "w") as f:
            f.write(html)

    def generate_rss(self, events):
        fg = FeedGenerator()
        fg.id("https://status.sarasfinance.com/")
        fg.title("Saras Finance - PulseCheck Status")
        fg.link(href="https://status.sarasfinance.com/", rel="alternate")
        fg.description("Real-time health status for Saras Finance services")

        if not events:
            fe = fg.add_entry()
            fe.id("all-systems-operational")
            fe.title("✅ All Systems Operational")
            fe.content("All services are currently reporting normal status.")
            fe.pubDate(datetime.now(timezone.utc))
        else:
            for event in events:
                fe = fg.add_entry()
                fe.id(event["id"])
                fe.title(event["title"])
                fe.content(event["content"])
                fe.pubDate(datetime.fromtimestamp(event["time"], tz=timezone.utc))

        fg.rss_file("../rss.xml")

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
        events = self.collect_incidents()
        self.generate_status_page(events)
        self.generate_rss(events)


if __name__ == "__main__":
    Monitor().run()
