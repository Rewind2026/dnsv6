"""
安全工具模块 - IP访问控制和登录认证
"""
import ipaddress
import logging
from functools import wraps
from flask import request, jsonify, session
from app.models import Database

logger = logging.getLogger(__name__)


def is_private_ip(ip: str) -> bool:
    """检查IP是否为内网地址"""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return True
        
        ip_str = str(ip)
        if ip_str.startswith('172.'):
            second = int(ip_str.split('.')[1])
            if 16 <= second <= 31:
                return True
            if 168 <= second <= 254:
                return True
        
        if ip_str.startswith('192.168.'):
            return True
        
        if ip_str.startswith('192.0.'):
            return True
        
        if ip_str.startswith('10.'):
            return True
        
        if ip_str.startswith('127.'):
            return True
        
        if ip_str.startswith('100.'):
            second = int(ip_str.split('.')[1])
            if 64 <= second <= 127:
                return True
        
        return False
    except ValueError:
        return False


def get_server_internal_ips() -> list:
    """获取服务器所有内网IPv4地址"""
    import socket
    import os
    internal_ips = []
    
    try:
        hostname = socket.gethostname()
        addresses = socket.getaddrinfo(hostname, None)
        for addr_info in addresses:
            ip = addr_info[4][0]
            if ip and not ip.startswith('::'):
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private:
                        internal_ips.append(ip)
                except:
                    pass
    except:
        pass
    
    if not internal_ips:
        try:
            import subprocess
            result = subprocess.run(
                ['hostname', '-I'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                for ip in result.stdout.strip().split():
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj.version == 4:
                            internal_ips.append(ip)
                    except:
                        pass
        except:
            pass
    
    if not internal_ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
            if local_ip:
                internal_ips.append(local_ip)
        except:
            pass
    
    logger.info(f"[安全] 服务器内网IP列表: {internal_ips}")
    if not internal_ips:
        logger.warning("[安全] 无法获取服务器内网IP，同网段判断将失效")
    return internal_ips


def is_same_network_segment(client_ip: str) -> bool:
    """检查客户端IP是否与服务器在同一内网段
    
    判断逻辑：
    1. 获取服务器所有内网IP
    2. 检查客户端IP是否与服务器任意一个IP在同一C段 (/24)
    3. 不依赖IP类型判断，只看是否同段
    """
    try:
        client = ipaddress.ip_address(client_ip)
        if not isinstance(client, ipaddress.IPv4Address):
            return False
        
        internal_ips = get_server_internal_ips()
        
        for server_ip in internal_ips:
            try:
                server = ipaddress.ip_address(server_ip)
                
                if isinstance(server, ipaddress.IPv4Address):
                    if server.ipv4_mapped:
                        server = server.ipv4_mapped
                    
                    if server.version == 4:
                        server_octets = server.exploded.split('.')
                        client_octets = client.exploded.split('.')
                        
                        if server_octets[0] == client_octets[0] and \
                           server_octets[1] == client_octets[1] and \
                           server_octets[2] == client_octets[2]:
                            logger.info(f"[安全] 同网段内网: {client_ip} 与服务器 {server_ip} 同段 (/24)")
                            return True
            except:
                continue
        
        return False
    except:
        return False


def get_network_prefix(ip: ipaddress.IPv4Address) -> str:
    """获取IP地址的网络前缀"""
    octets = ip.exploded.split('.')
    return f"{octets[0]}.{octets[1]}.{octets[2]}.0"


def is_ip_in_whitelist(ip: str, whitelist: list) -> bool:
    """检查IP是否在白名单中"""
    try:
        client = ipaddress.ip_address(ip)
        for whitelist_ip in whitelist:
            try:
                if '/' in whitelist_ip:
                    network = ipaddress.ip_network(whitelist_ip, strict=False)
                    if client in network:
                        return True
                else:
                    if client == ipaddress.ip_address(whitelist_ip):
                        return True
            except ValueError:
                continue
        return False
    except ValueError:
        return False


def get_client_ip() -> str:
    """获取客户端真实IP地址"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr


def get_ip_whitelist() -> list:
    """获取IP白名单配置"""
    db = Database()
    whitelist_str = db.get_app_config('ip_whitelist')
    if whitelist_str:
        return [ip.strip() for ip in whitelist_str.split(',') if ip.strip()]
    return []


def check_public_access(require_auth: bool = False):
    """
    检查是否允许公网访问
    
    参数:
        require_auth: 是否同时要求登录认证
    
    返回: (允许访问: bool, 客户端IP: str, 原因: str)
    """
    client_ip = get_client_ip()
    
    if is_private_ip(client_ip):
        logger.info(f"[安全] 内网IP访问允许: {client_ip}")
        return True, client_ip, "内网IP"
    
    if is_same_network_segment(client_ip):
        logger.info(f"[安全] 同网段内网访问允许: {client_ip}")
        return True, client_ip, "同网段内网"
    
    whitelist = get_ip_whitelist()
    if whitelist and is_ip_in_whitelist(client_ip, whitelist):
        logger.info(f"[安全] 白名单IP访问允许: {client_ip}")
        return True, client_ip, "IP白名单"
    
    db = Database()
    allow_public = db.get_app_config('allow_public_access')
    
    if allow_public != '1' and allow_public != 'true':
        logger.warning(f"[安全] 公网访问被拒绝: {client_ip}, 原因: 公网访问未开启")
        return False, client_ip, "公网访问未开启"
    
    if require_auth:
        if 'user_id' not in session:
            logger.warning(f"[安全] 公网访问被拒绝: {client_ip}, 原因: 未登录认证")
            return False, client_ip, "未登录认证"
    
    logger.info(f"[安全] 公网访问允许(已开启+已登录): {client_ip}")
    return True, client_ip, "已开启公网访问"


def require_private_ip(f):
    """装饰器：要求必须是内网IP或已开启公网访问才能访问"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        allowed, client_ip, reason = check_public_access()
        
        if not allowed:
            return jsonify({
                'success': False,
                'message': f'禁止公网访问: {reason}，请在内网环境使用或开启公网访问权限',
                'client_ip': client_ip
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_login_or_private_ip(f):
    """装饰器：要求登录或内网IP才能访问"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        allowed, client_ip, reason = check_public_access(require_auth=True)
        
        if not allowed:
            return jsonify({
                'success': False,
                'message': f'禁止访问: {reason}，请登录账号或在内网环境使用',
                'client_ip': client_ip
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


def can_modify_public_access():
    """
    检查是否可以修改公网访问设置
    只有内网IP、同网段IP、白名单IP或已登录用户可以修改
    """
    allowed, client_ip, reason = check_public_access(require_auth=True)
    return allowed


def get_access_info():
    """获取当前访问状态信息"""
    client_ip = get_client_ip()
    is_private = is_private_ip(client_ip)
    is_same_segment = is_same_network_segment(client_ip)
    whitelist = get_ip_whitelist()
    in_whitelist = is_ip_in_whitelist(client_ip, whitelist) if whitelist else False
    
    db = Database()
    allow_public = db.get_app_config('allow_public_access')
    allow_public_bool = allow_public == '1' or allow_public == 'true'
    
    is_logged_in = 'user_id' in session
    
    can_access = is_private or is_same_segment or in_whitelist or allow_public_bool
    can_modify = is_private or is_same_segment or in_whitelist or (allow_public_bool and is_logged_in)
    
    return {
        'client_ip': client_ip,
        'is_private': is_private,
        'is_same_segment': is_same_segment,
        'in_whitelist': in_whitelist,
        'allow_public': allow_public_bool,
        'is_logged_in': is_logged_in,
        'can_access': can_access,
        'can_modify': can_modify
    }
