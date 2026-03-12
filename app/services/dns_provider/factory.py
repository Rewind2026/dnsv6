from typing import Optional
from .aliyun import AliyunDNSProvider
from .cloudflare import CloudflareDNSProvider
from . import DNSProviderBase


class DNSProviderFactory:
    PROVIDERS = {
        'aliyun': AliyunDNSProvider,
        'cloudflare': CloudflareDNSProvider,
    }

    @classmethod
    def create(cls, provider: str, **kwargs) -> Optional[DNSProviderBase]:
        provider_class = cls.PROVIDERS.get(provider.lower())
        if provider_class:
            return provider_class(**kwargs)
        return None

    @classmethod
    def get_available_providers(cls) -> list:
        return list(cls.PROVIDERS.keys())
