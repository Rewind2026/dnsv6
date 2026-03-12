import requests
import hashlib
import hmac
import base64
import time
from urllib.parse import quote, urlencode
from typing import Optional, Dict, Any
from . import DNSProviderBase


class AliyunDNSProvider(DNSProviderBase):
    def __init__(self, access_key_id: str, access_key_secret: str):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.endpoint = "alidns.aliyuncs.com"
        self.version = "2015-01-09"

    def _sign(self, params: dict) -> str:
        sorted_params = sorted(params.items())
        canonicalized_query_string = '&'.join([
            f"{k}={quote(str(v), safe='')}"
            for k, v in sorted_params
        ])
        string_to_sign = f"GET&%2F&{quote(canonicalized_query_string, safe='')}"
        key = f"{self.access_key_secret}&".encode()
        return base64.b64encode(
            hmac.new(key, string_to_sign.encode(), hashlib.sha1).digest()
        ).decode()

    def _get_utc_timestamp(self) -> str:
        """获取正确的UTC时间戳，自动检测系统时区偏移"""
        import datetime
        import time
        
        # 优先使用 NTP 服务器获取真实UTC时间（最可靠，不依赖系统时区）
        try:
            import socket
            
            NTP_SERVER = 'pool.ntp.org'
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(5)
            ntp_packet = b'\x1b' + 47 * b'\0'
            client.sendto(ntp_packet, (NTP_SERVER, 123))
            data, _ = client.recvfrom(1024)
            client.close()
            
            ntp_time = int.from_bytes(data[40:44], 'big')
            unix_time = ntp_time - 2208988800
            unix_time -= 30  # 减去30秒缓冲
            
            timestamp = datetime.datetime.utcfromtimestamp(unix_time).strftime('%Y-%m-%dT%H:%M:%SZ')
            print(f"[时间戳] NTP时间: {timestamp}")
            return timestamp
        except Exception as e:
            print(f"[时间戳] NTP失败: {e}")
        
        # NTP失败时，使用 zoneinfo（Python 3.9+）
        try:
            from zoneinfo import ZoneInfo
            utc_now = datetime.datetime.now(ZoneInfo('UTC'))
            timestamp = utc_now.strftime('%Y-%m-%dT%H:%M:%SZ')
            print(f"[时间戳] zoneinfo: {timestamp}")
            return timestamp
        except Exception as e:
            print(f"[时间戳] zoneinfo失败: {e}")
        
        # 回退到简单方法
        offset = time.timezone
        local_ts = time.time()
        utc_ts = local_ts + offset
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(utc_ts))
        print(f"[时间戳] 回退方法: {timestamp}")
        return timestamp
        try:
            import socket
            # 连接NTP服务器获取时间
            NTP_SERVER = 'pool.ntp.org'
            PORT = 123
            
            # 构造NTP请求包
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(5)
            ntp_packet = b'\x1b' + 47 * b'\0'
            client.sendto(ntp_packet, (NTP_SERVER, PORT))
            data, _ = client.recvfrom(1024)
            client.close()
            
            # 解析NTP时间戳（从字节79-82获取）
            ntp_time = int.from_bytes(data[40:44], 'big')
            # NTP时间戳从1900年开始，需要转换为Unix时间戳（从1970年开始）
            # NTP: 2208988800 = (1970-1900)*365.25*24*60*60
            unix_time = ntp_time - 2208988800
            
            # 减去30秒缓冲
            unix_time -= 30
            timestamp = datetime.datetime.utcfromtimestamp(unix_time).strftime('%Y-%m-%dT%H:%M:%SZ')
            return timestamp
        except Exception as e:
            print(f"[时间戳] NTP获取失败: {e}")
        
        # 方法4: 回退到简单方法
        # 使用 time.timezone 反向计算
        offset = time.timezone  # 秒数
        local_ts = time.time()
        utc_ts = local_ts + offset  # 减去系统认为的偏移
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(utc_ts))
        return timestamp

    def _request(self, action: str, params: dict, retry_count: int = 0) -> dict:
        # 生成时间戳（UTC时间），自动处理时区
        timestamp = self._get_utc_timestamp()
        
        common_params = {
            'Format': 'JSON',
            'Version': self.version,
            'AccessKeyId': self.access_key_id,
            'SignatureMethod': 'HMAC-SHA1',
            'Timestamp': timestamp,
            'SignatureVersion': '1.0',
            'SignatureNonce': str(time.time()),
            'Action': action
        }
        common_params.update(params)

        common_params['Signature'] = self._sign(common_params)

        url = f"https://{self.endpoint}/?{urlencode(common_params)}"
        
        # 调试输出
        print(f"\n[阿里云 API 调试] 动作：{action}")
        print(f"[阿里云 API 调试] 时间戳：{timestamp}")
        print(f"[阿里云 API 调试] URL: {url}")
        
        try:
            resp = requests.get(url, timeout=10)
            print(f"[阿里云 API 调试] 状态码：{resp.status_code}")
            result = resp.json()
            print(f"[阿里云 API 调试] 响应：{result}")
            
            # 检查是否有错误
            if 'Code' in result:
                print(f"[阿里云 API 调试] ⚠️ 错误 - Code: {result.get('Code')}, Message: {result.get('Message')}")
                
                # 时间戳过期错误，重试多次
                if result.get('Code') == 'InvalidTimeStamp.Expired' and retry_count < 3:
                    wait_time = (retry_count + 1) * 2  # 2秒, 4秒, 6秒
                    print(f"[阿里云 API 调试] 时间戳过期，等待{wait_time}秒后重试 ({retry_count + 1}/3)...")
                    time.sleep(wait_time)
                    return self._request(action, params, retry_count + 1)
            
            return result
        except Exception as e:
            print(f"[阿里云 API 调试] ❌ 异常：{str(e)}")
            return {'Code': 'RequestError', 'Message': str(e)}

    def _extract_domain(self, domain: str) -> tuple:
        """
        解析完整域名，返回 (根域名，主机记录)
        例如:
        - rewind2023.cn -> ('rewind2023.cn', '@')
        - www.rewind2023.cn -> ('rewind2023.cn', 'www')
        - test.api.rewind2023.cn -> ('rewind2023.cn', 'test.api')
        """
        parts = domain.split('.')
        
        # 处理根域名情况（如 rewind2023.cn）
        if len(parts) == 2:
            root_domain = domain
            rr = "@"
        else:
            # 提取根域名（最后两部分）
            root_domain = '.'.join(parts[-2:])
            # 提取主机记录（去掉根域名部分）
            rr_parts = parts[:-2]
            rr = '.'.join(rr_parts) if rr_parts else "@"
        
        return root_domain, rr

    def get_record_id(self, domain: str, rr: str = None, record_type: str = None) -> Optional[str]:
        # 始终解析域名，获取根域名和主机记录
        root_domain, extracted_rr = self._extract_domain(domain)
        # 如果传入了rr参数，使用传入的；否则使用解析出来的
        if rr is None:
            rr = extracted_rr

        result = self._request('DescribeDomainRecords', {
            'DomainName': root_domain
        })

        if 'DomainRecords' in result:
            for record in result['DomainRecords']['Record']:
                # 同时匹配 RR 和记录类型（如果提供了类型）
                if record['RR'] == rr:
                    if record_type is None or record['Type'] == record_type:
                        return record['RecordId']
        return None

    def query_record(self, domain: str, record_type: str) -> Optional[str]:
        root_domain, rr = self._extract_domain(domain)

        result = self._request('DescribeDomainRecords', {
            'DomainName': root_domain
        })

        if 'DomainRecords' in result:
            for record in result['DomainRecords']['Record']:
                if record['RR'] == rr and record['Type'] == record_type:
                    return record['Value']
        return None

    def update_record(self, domain: str, record_type: str, value: str,
                     rr: str = "@", ttl: int = 600) -> Dict[str, Any]:
        # 从完整域名解析出根域名和主机记录
        root_domain, rr = self._extract_domain(domain)

        print(f"\n[DNS 更新] 域名：{domain}, 类型：{record_type}, IP: {value}, RR: {rr}, 根域名：{root_domain}")
        
        old_ip = self.query_record(domain, record_type)
        print(f"[DNS 更新] 当前解析的 IP: {old_ip}")
        
        # 传入记录类型，确保获取正确的记录ID
        record_id = self.get_record_id(domain, rr, record_type)
        print(f"[DNS 更新] 记录 ID: {record_id if record_id else '不存在'}")

        # 检查 IP 是否相同
        if old_ip == value:
            print(f"[DNS 更新] IP 未变化，跳过更新")
            return {
                "success": True,
                "message": "IP 未变化，无需更新",
                "old_ip": old_ip,
                "unchanged": True
            }

        if record_id:
            print(f"[DNS 更新] >> 执行更新操作 (UpdateDomainRecord)")
            result = self._request('UpdateDomainRecord', {
                'RecordId': record_id,
                'RR': rr,
                'Type': record_type,
                'Value': value,
                'TTL': ttl
            })
            success = 'RecordId' in result
        else:
            print(f"[DNS 更新] >> 执行添加操作 (AddDomainRecord)")
            result = self._request('AddDomainRecord', {
                'DomainName': root_domain,
                'RR': rr,
                'Type': record_type,
                'Value': value,
                'TTL': ttl
            })
            success = 'RecordId' in result

        # 获取详细的错误信息
        message = result.get('Message', '')
        if not success:
            # 阿里云常见错误
            code = result.get('Code', '')
            if code == 'DomainRecordDuplicate':
                message = '记录已存在且相同'
            elif code == 'DomainRecordLocked':
                message = '记录被锁定，请稍后再试（API 频率限制）'
            elif code == 'Throttling':
                message = '请求过于频繁，请稍后再试'
            elif code:
                message = f'{code}: {message}'
            else:
                message = message or '更新失败'
        
        print(f"[DNS 更新] 结果：success={success}, message={message}")

        return {
            "success": success,
            "message": message,
            "old_ip": old_ip
        }

    def delete_record(self, domain: str, record_type: str) -> Dict[str, Any]:
        """删除DNS记录"""
        root_domain, rr = self._extract_domain(domain)
        
        print(f"\n[DNS 删除] 域名：{domain}, 类型：{record_type}, RR: {rr}, 根域名：{root_domain}")
        
        # 获取记录ID（传入记录类型确保删除正确的记录）
        record_id = self.get_record_id(domain, rr, record_type)
        
        if not record_id:
            print(f"[DNS 删除] 记录不存在，无需删除")
            return {
                "success": True,
                "message": "记录不存在",
                "deleted": False
            }
        
        print(f"[DNS 删除] 找到记录 ID: {record_id}，执行删除")
        
        result = self._request('DeleteDomainRecord', {
            'RecordId': record_id
        })
        
        success = 'RecordId' in result
        
        if not success:
            code = result.get('Code', '')
            message = result.get('Message', '删除失败')
            if code:
                message = f'{code}: {message}'
            print(f"[DNS 删除] 失败: {message}")
        else:
            print(f"[DNS 删除] 成功")
        
        return {
            "success": success,
            "message": result.get('Message', '删除成功' if success else '删除失败'),
            "deleted": success
        }
