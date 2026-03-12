import requests
from typing import Optional, Dict, Any
from . import DNSProviderBase


class CloudflareDNSProvider(DNSProviderBase):
    def __init__(self, api_token: str, zone_id: str = None):
        self.api_token = api_token
        self.zone_id = zone_id
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }

    def _get_zone_id(self, domain: str) -> Optional[str]:
        if self.zone_id:
            return self.zone_id

        parts = domain.split('.')
        if len(parts) >= 2:
            zone_name = '.'.join(parts[-2:])

        try:
            resp = requests.get(
                f"{self.base_url}/zones",
                params={'name': zone_name},
                headers=self.headers,
                timeout=10
            )
            data = resp.json()
            if data.get('success') and data['result']:
                return data['result'][0]['id']
        except Exception:
            pass
        return None

    def query_record(self, domain: str, record_type: str) -> Optional[str]:
        zone_id = self._get_zone_id(domain)
        if not zone_id:
            return None

        try:
            resp = requests.get(
                f"{self.base_url}/zones/{zone_id}/dns_records",
                params={'name': domain, 'type': record_type},
                headers=self.headers,
                timeout=10
            )
            data = resp.json()
            if data.get('success') and data['result']:
                return data['result'][0]['content']
        except Exception:
            pass
        return None

    def get_record_id(self, domain: str, record_type: str = 'A') -> Optional[str]:
        zone_id = self._get_zone_id(domain)
        if not zone_id:
            return None

        try:
            resp = requests.get(
                f"{self.base_url}/zones/{zone_id}/dns_records",
                params={'name': domain, 'type': record_type},
                headers=self.headers,
                timeout=10
            )
            data = resp.json()
            if data.get('success') and data['result']:
                return data['result'][0]['id']
        except Exception:
            pass
        return None

    def update_record(self, domain: str, record_type: str, value: str,
                     rr: str = "@", ttl: int = 600) -> Dict[str, Any]:
        zone_id = self._get_zone_id(domain)
        if not zone_id:
            return {"success": False, "message": "无法获取Zone ID", "old_ip": None}

        record_id = self.get_record_id(domain, record_type)
        old_ip = self.query_record(domain, record_type)

        ttl = 1

        try:
            if record_id:
                resp = requests.put(
                    f"{self.base_url}/zones/{zone_id}/dns_records/{record_id}",
                    json={
                        'type': record_type,
                        'name': domain,
                        'content': value,
                        'ttl': ttl
                    },
                    headers=self.headers,
                    timeout=10
                )
            else:
                resp = requests.post(
                    f"{self.base_url}/zones/{zone_id}/dns_records",
                    json={
                        'type': record_type,
                        'name': domain,
                        'content': value,
                        'ttl': ttl
                    },
                    headers=self.headers,
                    timeout=10
                )

            data = resp.json()
            return {
                "success": data.get('success', False),
                "message": data.get('errors', [{}])[0].get('message', ''),
                "old_ip": old_ip
            }
        except Exception as e:
            return {
                "success": False,
                "message": str(e),
                "old_ip": old_ip
            }
