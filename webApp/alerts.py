import os
import requests
from datetime import datetime, timezone
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


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
        message = (
            f"🔴 {data['group']} - {data['name']} is DOWN\nStatus: {data['status']}"
            if data["status"]
            else f"Error: {data['error']}"
        )
        try:
            requests.post(
                "https://api.pushover.net/1/messages.json",
                data={
                    "token": token,
                    "user": user_key,
                    "message": message,
                    "priority": 1 if data.get("critical") else 0,
                },
                timeout=10,
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
            plain_text_content=f"Service: {data['name']} ({data['group']}) failed.\nTime: {data['timestamp']}",
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


class AlertDispatcher:
    def __init__(self, alerts_config):
        self.alerts_config = alerts_config or {}
        self.providers = [PushoverAlert(), SendGridAlert(), WebhookAlert()]

    def notify(self, name, group, status, error, critical):
        data = {
            "name": name,
            "group": group,
            "status": status,
            "error": error,
            "critical": critical,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        for provider in self.providers:
            provider.send(data, self.alerts_config)
