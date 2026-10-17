from datetime import datetime, timezone
from jinja2 import Template
from feedgen.feed import FeedGenerator


class StatusRenderer:
    @staticmethod
    def generate_status_page(results, events, template_path="status_template.html", output_path="../index.html"):
        sorted_results = {}
        total_services = 0
        operational_services = 0
        degraded_services = 0
        offline_services = 0
        maintenance_services = 0

        for group_name in sorted(results.keys(), key=lambda s: s.lower()):
            svcs = sorted(results[group_name], key=lambda x: x["name"].lower())
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
            "all_operational": offline_services == 0 and degraded_services == 0,
        }

        now_utc = datetime.now(timezone.utc)
        with open(template_path, "r") as f:
            template = Template(f.read())

        html = template.render(
            results=sorted_results,
            summary=summary,
            incidents=events,
            last_updated=now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            last_updated_iso=now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        with open(output_path, "w") as f:
            f.write(html)

    @staticmethod
    def generate_rss(events, output_path="../rss.xml"):
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
                fe.id(str(event["id"]))
                fe.title(f"[{event['id']}] {event['title']} ({event['status']})")
                updates = event.get("updates") or []
                if updates:
                    lines = [f"[{u['time_display']}] {u['status']}: {u['note']}" for u in updates]
                    fe.content("\n".join(lines))
                else:
                    fe.content(event.get("content", ""))
                fe.pubDate(datetime.fromtimestamp(event["time"], tz=timezone.utc))

        fg.rss_file(output_path)
