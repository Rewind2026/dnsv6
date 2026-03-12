from abc import ABC, abstractmethod
from typing import Optional, Dict, Any


class DNSProviderBase(ABC):
    @abstractmethod
    def update_record(self, domain: str, record_type: str, value: str,
                     rr: str = "@", ttl: int = 600) -> Dict[str, Any]:
        pass

    @abstractmethod
    def query_record(self, domain: str, record_type: str) -> Optional[str]:
        pass

    def get_record_id(self, domain: str, rr: str, record_type: str = None) -> Optional[str]:
        pass

    def delete_record(self, domain: str, record_type: str) -> Dict[str, Any]:
        """删除DNS记录，子类可选择性实现"""
        return {"success": False, "message": "删除功能未实现", "deleted": False}
