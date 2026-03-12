import requests
import re
import subprocess
import socket
import ipaddress
from typing import Optional, List, Tuple


class IPDetector:
    def __init__(self):
        # 国内IP检测API，避免走代理
        self.ipv4_check_urls = [
            'https://www.taobao.com/help/getip.php',  # 淘宝IP接口
            'https://myip.ipip.net/',  # ipip.net
            'https://api.ipify.org?format=text',
            'https://ipinfo.io/ip',
        ]
        self.ipv6_check_urls = [
            'https://api64.ipify.org?format=text',
            'https://ipv6.ipinfo.io/ip',
            'https://test6.ustc.edu.cn/',  # 中科大IPv6测试
        ]
        self.china_ipv6_prefixes = ['2408', '2409', '2410', '2411', '2412', '2413', '2414', '2415', '2402', '2403', '2404', '2405', '2406', '2407', '2a02', '2a03', '2a04', '2a05', '2a06', '2a07']

    def _get_session(self):
        session = requests.Session()
        session.trust_env = False
        return session

    def _is_valid_ipv4(self, ip: str) -> bool:
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        parts = ip.split('.')
        return all(0 <= int(p) <= 255 for p in parts)

    def _is_valid_ipv6(self, ip: str) -> bool:
        """验证IPv6地址是否有效（使用标准库）"""
        if not ip or len(ip) < 3:
            return False
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False
    
    def _is_global_unicast_ipv6(self, ip: str) -> bool:
        """检查是否为全球单播地址（GUA），过滤fe80::和fd00::等"""
        try:
            addr = ipaddress.IPv6Address(ip)
            # 排除链路本地地址(fe80::/10)、ULA(fd00::/8)、回环(::1)、多播(ff00::/8)
            return (
                addr.is_global and  # 2000::/3 范围
                not addr.is_link_local and  # fe80::/10
                not addr.is_loopback and  # ::1
                not addr.is_multicast  # ff00::/8
            )
        except ValueError:
            return False

    def _is_temporary_ipv6(self, ip: str) -> bool:
        """检查是否为临时IPv6地址（RFC 4941）
        
        临时地址特征：
        - 后缀随机生成（不同于EUI-64的FF:FE格式）
        - 用于对外连接，保护隐私
        - 不应该用于DDNS（因为会变化）
        
        判断方法：
        - 检查第4个16位组（第64-79位）是否为0xfffe（EUI-64）
        - 如果不是0xfffe，则可能是临时地址
        """
        try:
            addr = ipaddress.IPv6Address(ip)
            # 获取IPv6地址的整数表示
            ip_int = int(addr)
            
            # 提取第64-79位（第4个16位组）
            # IPv6地址结构：[0-63位前缀][64-79位][80-127位接口标识]
            fourth_group = (ip_int >> 64) & 0xFFFF
            
            # EUI-64格式的第4组是0xfffe
            # 如果不是0xfffe，可能是临时地址
            if fourth_group != 0xfffe:
                return True
            
            # 进一步检查：临时地址的后缀通常是纯随机的
            # EUI-64的后缀包含MAC地址信息，有一定规律
            return False
        except ValueError:
            return False

    def _is_stable_ipv6(self, ip: str) -> bool:
        """检查是否为稳定的IPv6地址（适合DDNS）
        
        稳定的地址：
        - 基于EUI-64（由MAC地址生成）
        - 不是临时地址
        - 不是隐私扩展地址
        """
        if not self._is_global_unicast_ipv6(ip):
            return False
        return not self._is_temporary_ipv6(ip)

    def _is_china_ipv6(self, ip: str) -> bool:
        for prefix in self.china_ipv6_prefixes:
            if ip.startswith(prefix):
                return True
        return False

    def _get_ipv6_prefix(self, full_ipv6: str) -> str:
        """提取IPv6前缀（使用标准库）"""
        if not full_ipv6:
            return ''
        try:
            # 使用标准库处理IPv6前缀提取
            network = ipaddress.IPv6Network(f"{full_ipv6}/64", strict=False)
            return str(network.network_address)
        except ValueError:
            return ''

    def get_public_ipv4(self) -> Optional[str]:
        """获取公网IPv4，优先使用国内API避免代理"""
        import os
        # 设置环境变量禁用代理
        old_env = {}
        for key in ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']:
            if key in os.environ:
                old_env[key] = os.environ[key]
                del os.environ[key]
        
        try:
            session = self._get_session()
            for url in self.ipv4_check_urls:
                try:
                    resp = session.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, proxies={})
                    text = resp.text.strip()
                    
                    # 处理不同API的返回格式
                    if 'taobao' in url:
                        # 淘宝: ipCallback({"ip":"xxx.xxx.xxx.xxx"})
                        match = re.search(r'"ip":"(\d+\.\d+\.\d+\.\d+)"', text)
                        if match:
                            text = match.group(1)
                    elif 'ipip.net' in url:
                        # ipip.net: 当前 IP：xxx.xxx.xxx.xxx
                        match = re.search(r'当前 IP[：:]\s*(\d+\.\d+\.\d+\.\d+)', text)
                        if match:
                            text = match.group(1)
                    
                    if self._is_valid_ipv4(text):
                        return text
                except Exception:
                    continue
            
            local_ipv4 = self.get_local_ipv4()
            if local_ipv4:
                print(f"[IP检测] 外部API获取IPv4失败，使用本地IPv4: {local_ipv4}")
                return local_ipv4
            
            return None
        finally:
            # 恢复环境变量
            for key, val in old_env.items():
                os.environ[key] = val

    def get_public_ipv6(self) -> Optional[str]:
        session = self._get_session()
        for url in self.ipv6_check_urls:
            try:
                resp = session.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
                text = resp.text.strip()
                if self._is_valid_ipv6(text):
                    return text
            except Exception:
                continue
        
        local_ipv6 = self.get_local_ipv6()
        if local_ipv6:
            print(f"[IP检测] 外部API获取IPv6失败，使用本地IPv6: {local_ipv6}")
            return local_ipv6
        
        return None

    def get_local_ipv4(self) -> Optional[str]:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            if self._is_valid_ipv4(local_ip):
                return local_ip
        except:
            pass
        finally:
            if s:
                try:
                    s.close()
                except:
                    pass
        return None
    
    def get_ip_from_domain(self, domain: str, ip_type: str = 'ipv4') -> Optional[str]:
        """从域名解析IP
        
        Args:
            domain: 域名
            ip_type: 'ipv4' 或 'ipv6'
        
        Returns:
            解析到的IP，未解析到返回None
        """
        import socket
        
        try:
            if ip_type == 'ipv6':
                result = socket.getaddrinfo(domain, None, socket.AF_INET6)
                if result:
                    return result[0][4][0]
            else:
                result = socket.gethostbyname(domain)
                if result:
                    return result
        except socket.gaierror:
            print(f"[域名解析] 无法解析域名 {domain}")
        except Exception as e:
            print(f"[域名解析] 解析域名 {domain} 失败: {e}")
        
        return None

    def get_local_ipv6(self, prefer_stable: bool = True) -> Optional[str]:
        """获取本地IPv6地址（只返回全球单播地址GUA，过滤fe80::和fd00::）
        
        Args:
            prefer_stable: 是否优先选择稳定的EUI-64地址（而非临时地址）
        """
        ipv6_list = []
        
        s = None
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.connect(('2001:4860:4860::8888', 80))
            local_ip = s.getsockname()[0]
            # 检查是否为全球单播地址（排除fe80::和fd00::）
            if self._is_global_unicast_ipv6(local_ip):
                ipv6_list.append(local_ip)
        except:
            pass
        finally:
            if s:
                try:
                    s.close()
                except:
                    pass

        try:
            cmd = 'ipconfig'
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, encoding='utf-8', errors='ignore')
            for line in result.stdout.split('\n'):
                if 'IPv6' in line and '.' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        ip = parts[1].strip()
                        # 只收集全球单播地址
                        if self._is_global_unicast_ipv6(ip) and ip not in ipv6_list:
                            ipv6_list.append(ip)
        except:
            pass
        
        if not ipv6_list:
            return None
        
        # 如果优先选择稳定地址，过滤掉临时地址
        if prefer_stable:
            stable_ips = [ip for ip in ipv6_list if self._is_stable_ipv6(ip)]
            if stable_ips:
                return stable_ips[0]
            # 如果没有稳定地址，返回第一个（可能是临时地址）
            return ipv6_list[0]
        
        return ipv6_list[0]

    def get_local_ipv6_list(self) -> List[str]:
        ipv6_list = []
        
        s = None
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.connect(('2001:4860:4860::8888', 80))
            local_ip = s.getsockname()[0]
            if self._is_valid_ipv6(local_ip):
                ipv6_list.append(local_ip)
        except:
            pass
        finally:
            if s:
                try:
                    s.close()
                except:
                    pass

        try:
            cmd = 'ipconfig'
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, encoding='utf-8', errors='ignore')
            for line in result.stdout.split('\n'):
                if 'IPv6' in line and '.' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        ip = parts[1].strip()
                        if self._is_valid_ipv6(ip) and ip not in ipv6_list:
                            ipv6_list.append(ip)
        except:
            pass

        return ipv6_list[:5]

    def get_ipv6_prefix_from_route(self) -> Optional[str]:
        """从 ip -6 route 获取默认IPv6前缀（DHCPv6-PD）"""
        import platform
        system = platform.system()
        
        try:
            if system == 'Windows':
                result = subprocess.run(
                    ['netsh', 'interface', 'ipv6', 'show', 'route'],
                    capture_output=True, text=True, timeout=5, encoding='utf-8', errors='ignore'
                )
            else:
                result = subprocess.run(
                    ['ip', '-6', 'route', 'show', 'default'],
                    capture_output=True, text=True, timeout=5
                )
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                if 'from' in line and '/' in line:
                    match = re.search(r'from\s+([0-9a-f:]+)/\d+', line)
                    if match:
                        prefix = match.group(1)
                        if self._is_valid_ipv6(prefix):
                            return prefix
                
                if 'via' not in line and '/' in line:
                    match = re.search(r'([0-9a-f:]+)/\d+', line)
                    if match:
                        prefix = match.group(1)
                        if self._is_valid_ipv6(prefix):
                            return prefix
                            
        except Exception as e:
            print(f"[IP检测] 获取IPv6路由前缀失败: {e}")
        
        return None

    def get_ipv6_info(self) -> Tuple[Optional[str], Optional[str], List[str]]:
        public_ipv6 = self.get_public_ipv6()
        local_ipv6 = self.get_local_ipv6()
        local_ipv6_list = self.get_local_ipv6_list()
        
        full_ipv6 = public_ipv6 if public_ipv6 else local_ipv6
        
        prefix_ipv6 = self._get_ipv6_prefix(full_ipv6) if full_ipv6 else None
        
        if not prefix_ipv6:
            route_prefix = self.get_ipv6_prefix_from_route()
            if route_prefix:
                prefix_ipv6 = route_prefix
                if full_ipv6 and not full_ipv6.startswith(route_prefix):
                    full_ipv6 = route_prefix + '::1'
        
        return prefix_ipv6, full_ipv6, local_ipv6_list

    def get_best_ipv6(self) -> Optional[str]:
        public_ipv6 = self.get_public_ipv6()
        if public_ipv6:
            return public_ipv6
        
        local_ipv6 = self.get_local_ipv6()
        return local_ipv6

    def get_ip_from_interface(self, interface_name: str, ipv6: bool = True) -> Optional[str]:
        try:
            cmd = ['ip', '-6', 'addr', 'show', interface_name] if ipv6 else ['ip', 'addr', 'show', interface_name]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if ipv6:
                    if 'inet6' in line and 'global' in line:
                        match = re.search(r'([0-9a-f:]+)/\d+', line)
                        if match:
                            return match.group(1)
                else:
                    if 'inet ' in line and 'global' in line:
                        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/\d+', line)
                        if match:
                            return match.group(1)
        except Exception:
            pass
        return None

    def get_ip_from_command(self, command: str) -> Optional[str]:
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            return result.stdout.strip()
        except Exception:
            return None

    def extract_ipv6_prefix(self, full_ipv6: str, prefix_len: int = 64) -> str:
        """提取IPv6前缀（使用标准库）"""
        if not full_ipv6:
            return ''
        try:
            # 先解析为IPv6地址，再转换为完整格式
            addr = ipaddress.IPv6Address(full_ipv6)
            # 获取完整格式的地址（展开::）
            full_addr_str = str(addr)
            # 提取前缀部分（前4组）
            parts = full_addr_str.split(':')
            prefix_parts = parts[:4]  # /64前缀是前4组
            return ':'.join(prefix_parts)
        except ValueError:
            return ''

    def combine_ipv6_address(self, prefix: str, suffix: str) -> str:
        """拼接IPv6前缀和后缀（使用标准库）
        
        Args:
            prefix: IPv6前缀，如 2408:822e:8a7:40f0
            suffix: 可以是::开头的后缀，也可以是完整的IPv6地址，或者是后64位
        
        Returns:
            完整的IPv6地址
        """
        try:
            # 清理前缀
            prefix = prefix.strip().rstrip(':')
            suffix = suffix.strip()
            
            # 如果后缀以::开头，说明已经是压缩格式
            if suffix.startswith('::'):
                # 使用标准库验证和格式化
                combined = f"{prefix}{suffix}"
                addr = ipaddress.IPv6Address(combined)
                return str(addr)
            
            # 处理后缀，提取后64位
            suffix_parts = suffix.split(':')
            if len(suffix_parts) >= 4:
                # 取后4组作为后缀
                suffix = ':'.join(suffix_parts[-4:])
            
            suffix = suffix.lstrip(':')
            
            # 使用整数运算拼接前缀和后缀
            prefix_int = int(ipaddress.IPv6Address(f"{prefix}::"))
            suffix_int = int(ipaddress.IPv6Address(f"::{suffix}"))
            combined_addr = ipaddress.IPv6Address(prefix_int | suffix_int)
            return str(combined_addr)
        except ValueError as e:
            # 如果标准库处理失败，回退到字符串拼接
            prefix = prefix.strip().rstrip(':')
            suffix = suffix.strip().lstrip(':')
            return f"{prefix}:{suffix}"
