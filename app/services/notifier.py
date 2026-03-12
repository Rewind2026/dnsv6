import requests
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class NotifyContext:
    ipv4_addr: Optional[str]
    ipv4_result: str
    ipv4_domains: str
    ipv6_addr: Optional[str]
    ipv6_result: str
    ipv6_domains: str


class NotifierBase(ABC):
    @abstractmethod
    def send(self, title: str, content: str) -> bool:
        pass


class WebhookNotifier(NotifierBase):
    def __init__(self, url: str, method: str = "POST",
                 headers: Dict[str, str] = None, template: str = None):
        self.url = url
        self.method = method.upper()
        self.headers = headers or {"Content-Type": "application/json"}
        self.template = template

    def send(self, title: str, content: str) -> bool:
        body = content
        if self.template:
            body = self.template.replace("#{title}", title).replace("#{content}", content)
        else:
            body = f"{title}\n{content}"

        try:
            if self.method == "GET":
                resp = requests.get(self.url, params={"msg": body}, timeout=10)
            else:
                resp = requests.request(
                    self.method, self.url,
                    data=body.encode('utf-8'),
                    headers=self.headers,
                    timeout=10
                )
            return resp.status_code < 400
        except Exception:
            return False


class DingTalkNotifier(NotifierBase):
    def __init__(self, webhook_url: str, secret: str = None):
        self.webhook_url = webhook_url
        self.secret = secret

    def send(self, title: str, content: str) -> bool:
        import time
        import hmac
        import hashlib
        import base64
        import urllib.parse

        if self.secret:
            timestamp = str(round(time.time() * 1000))
            secret_enc = self.secret.encode('utf-8')
            string_to_sign = f'{timestamp}\n{self.secret}'
            string_to_sign_enc = string_to_sign.encode('utf-8')
            hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
            sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
            url = f"{self.webhook_url}&timestamp={timestamp}&sign={sign}"
        else:
            url = self.webhook_url

        data = {
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": f"#### {title}\n{content}"
            }
        }

        try:
            resp = requests.post(url, json=data, timeout=10)
            return resp.json().get('errcode') == 0
        except Exception:
            return False


class ServerChanNotifier(NotifierBase):
    def __init__(self, send_key: str):
        self.send_key = send_key
        self.url = f"https://sctapi.ftqq.com/{send_key}.send"

    def send(self, title: str, content: str) -> bool:
        data = {
            "title": title,
            "desp": content
        }

        try:
            resp = requests.post(self.url, data=data, timeout=10)
            return resp.json().get('code') == 0
        except Exception:
            return False


class BarkNotifier(NotifierBase):
    def __init__(self, bark_key: str):
        self.bark_key = bark_key
        self.url = f"https://api.day.app/{bark_key}"

    def send(self, title: str, content: str) -> bool:
        data = {
            "title": title,
            "body": content
        }

        try:
            resp = requests.post(self.url, json=data, timeout=10)
            return resp.status_code == 200
        except Exception:
            return False


class NotificationManager:
    def __init__(self):
        self.notifiers: list = []

    def add_notifier(self, notifier: NotifierBase):
        self.notifiers.append(notifier)

    def notify(self, context: NotifyContext) -> Dict[str, bool]:
        results = {}

        content_parts = []
        if context.ipv4_addr:
            content_parts.append(f"IPv4: {context.ipv4_addr}")
            content_parts.append(f"结果: {context.ipv4_result}")
            content_parts.append(f"域名: {context.ipv4_domains}")
        if context.ipv6_addr:
            content_parts.append(f"IPv6: {context.ipv6_addr}")
            content_parts.append(f"结果: {context.ipv6_result}")
            content_parts.append(f"域名: {context.ipv6_domains}")

        content = "\n".join(content_parts)
        title = "DDNS更新通知"

        for i, notifier in enumerate(self.notifiers):
            try:
                results[f"notifier_{i}"] = notifier.send(title, content)
            except Exception:
                results[f"notifier_{i}"] = False

        return results
