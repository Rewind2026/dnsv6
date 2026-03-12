from flask import Blueprint, request, jsonify
from app.services.ddns import DDNSService, DeviceConfig
from app.services.dns_provider.factory import DNSProviderFactory
from app.services.ip_detector import IPDetector
from app.services.notifier import NotificationManager, NotifyContext
from app.models import Database
from app.utils.security import require_private_ip
import json
import re
import ipaddress
import logging

logger = logging.getLogger(__name__)

api = Blueprint('api', __name__, url_prefix='/api')
db = Database()
ddns_service = None
notifier = NotificationManager()


# 输入校验工具函数
def validate_device_id(device_id: str) -> tuple:
    """校验设备ID
    
    规则：
    - 长度1-50字符
    - 只允许字母、数字、下划线、连字符
    """
    if not device_id or len(device_id) < 1 or len(device_id) > 50:
        return False, "设备ID长度必须在1-50字符之间"
    if not re.match(r'^[a-zA-Z0-9_-]+$', device_id):
        return False, "设备ID只能包含字母、数字、下划线和连字符"
    return True, None


def validate_domain(domain: str) -> tuple:
    """校验域名
    
    规则：
    - 长度1-253字符
    - 符合DNS规范（支持通配符*）
    - 不允许纯IP地址作为域名
    - 支持国际化域名（IDN）的punycode格式如xn--xxx
    """
    if not domain or len(domain) < 1 or len(domain) > 253:
        return False, "域名长度必须在1-253字符之间"
    
    # 转换为小写并去除首尾空格
    domain = domain.strip().lower()
    
    # DNS标签规则：字母数字连字符，不以连字符开头结尾
    # 支持通配符*（如*.example.com）
    labels = domain.split('.')
    for i, label in enumerate(labels):
        if not label:
            return False, "域名标签不能为空"
        if len(label) > 63:
            return False, "域名标签长度必须在1-63字符之间"
        
        # 通配符只允许在第一个标签且单独使用
        if label == '*':
            if i != 0:
                return False, "通配符*只能用于子域名开头"
            continue
        
        # 支持标准DNS标签和punycode（xn--开头）
        if label.startswith('xn--'):
            # punycode标签：xn--后面只允许字母数字连字符
            if not re.match(r'^xn--[a-zA-Z0-9-]+$', label):
                return False, "国际化域名格式错误"
        else:
            # 标准DNS标签：字母数字连字符，不以连字符开头结尾
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
                return False, "域名包含非法字符"
    
    # 检查是否为纯IP地址（域名可以包含数字，但不能是纯IP格式）
    try:
        ipaddress.ip_address(domain)
        return False, "域名不能是纯IP地址"
    except ValueError:
        pass
    
    return True, None


def validate_ipv6_suffix(suffix: str) -> tuple:
    """校验IPv6后缀
    
    规则：
    - 必须是有效的IPv6地址格式（64位后缀）
    - 支持格式如:abcd:1234:5678:9abc 或完整IPv6
    - 后缀应该是接口标识符部分（后64位）
    """
    if not suffix:
        return True, None  # 空后缀表示使用完整IPv6
    
    suffix = suffix.strip()
    
    # 尝试作为完整IPv6校验
    try:
        addr = ipaddress.IPv6Address(suffix)
        # 如果是完整IPv6，检查后64位是否非零（有实际后缀）
        ip_int = int(addr)
        interface_id = ip_int & 0xFFFFFFFFFFFFFFFF
        if interface_id == 0:
            return False, "IPv6后缀不能全为零"
        return True, None
    except ValueError:
        pass
    
    # 尝试作为后缀部分校验（应该包含4个16位组）
    # 标准化后缀格式
    test_suffix = suffix
    if not test_suffix.startswith(':'):
        test_suffix = '::' + test_suffix
    
    try:
        # 尝试解析为完整IPv6（用零前缀填充）
        full_ip = ipaddress.IPv6Address(test_suffix)
        # 检查后64位是否非零
        ip_int = int(full_ip)
        interface_id = ip_int & 0xFFFFFFFFFFFFFFFF
        if interface_id == 0:
            return False, "IPv6后缀不能全为零"
        return True, None
    except ValueError:
        return False, "IPv6后缀格式无效，应为4组16进制数如:abcd:1234:5678:9abc"


def validate_ipv6_address(ip: str) -> tuple:
    """校验IPv6地址"""
    if not ip:
        return True, None
    try:
        addr = ipaddress.IPv6Address(ip)
        if not addr.is_global:
            return False, "IPv6地址必须是全球单播地址(GUA)"
        return True, None
    except ValueError:
        return False, "IPv6地址格式无效"


def validate_ipv4_address(ip: str) -> tuple:
    """校验IPv4地址"""
    if not ip:
        return True, None
    try:
        addr = ipaddress.IPv4Address(ip)
        if addr.is_private:
            return False, "IPv4地址不能是私有地址"
        if addr.is_loopback:
            return False, "IPv4地址不能是回环地址"
        return True, None
    except ValueError:
        return False, "IPv4地址格式无效"


def get_ddns_service():
    global ddns_service
    if ddns_service is None:
        config = db.get_dns_config()
        if config and config.get('access_key_id'):
            dns = DNSProviderFactory.create(
                config['provider'],
                access_key_id=config['access_key_id'],
                access_key_secret=config['access_key_secret']
            )
            detector = IPDetector()
            # 传入数据库实例，用于持久化IP状态
            ddns_service = DDNSService(dns, detector, db)

            devices = db.get_devices()
            device_configs = [
                DeviceConfig(
                    id=d['id'],
                    device_id=d['device_id'],
                    suffix=d.get('suffix', ''),
                    domain=d['domain'],
                    record_type=d['record_type'],
                    enabled=bool(d['enabled']),
                    ipv_type=d.get('ipv_type', 'ipv6'),
                    ipv6_mode=d.get('ipv6_mode', 'auto'),
                    manual_ipv6=d.get('manual_ipv6', ''),
                    ipv4_mode=d.get('ipv4_mode', 'auto'),
                    manual_ipv4=d.get('manual_ipv4', ''),
                    last_ipv4=d.get('last_ipv4'),
                    last_ipv6=d.get('last_ipv6'),
                    source_type=d.get('source_type', 'auto'),
                    source_domain=d.get('source_domain', '')
                )
                for d in devices
            ]
            ddns_service.set_devices(device_configs)

    return ddns_service


def refresh_ddns_service():
    global ddns_service
    ddns_service = None
    return get_ddns_service()


@api.route('/ip/detect', methods=['GET'])
def detect_ip():
    detector = IPDetector()
    ipv4 = detector.get_public_ipv4()
    prefix_ipv6, full_ipv6, local_ipv6_list = detector.get_ipv6_info()
    return jsonify({
        'ipv4': ipv4, 
        'ipv6': prefix_ipv6,
        'ipv6_full': full_ipv6,
        'ipv6_public': full_ipv6,
        'ipv6_local': local_ipv6_list
    })


@api.route('/config', methods=['GET', 'POST'])
@require_private_ip
def config():
    if request.method == 'GET':
        config_data = db.get_dns_config()
        if config_data:
            config_data.pop('access_key_secret', None)
        return jsonify(config_data or {})
    else:
        config_data = request.json
        db.save_dns_config(config_data)
        global ddns_service
        ddns_service = None
        return jsonify({'success': True})


@api.route('/devices', methods=['GET', 'POST'])
@require_private_ip
def devices():
    if request.method == 'GET':
        devices_list = db.get_devices()
        for device in devices_list:
            device['enabled'] = bool(device.get('enabled', 1))
            # status 已由 get_devices() 方法根据日志计算，无需覆盖
        return jsonify(devices_list)
    else:
        device = request.json
        
        # 输入校验
        device_id = device.get('device_id', '').strip()
        domain = device.get('domain', '').strip().lower()
        suffix = device.get('suffix', '').strip()
        manual_ipv6 = device.get('manual_ipv6', '').strip()
        manual_ipv4 = device.get('manual_ipv4', '').strip()
        
        # 校验设备ID
        valid, error = validate_device_id(device_id)
        if not valid:
            return jsonify({'success': False, 'error': error}), 400
        
        # 校验域名
        valid, error = validate_domain(domain)
        if not valid:
            return jsonify({'success': False, 'error': error}), 400
        
        # 校验IPv6后缀
        valid, error = validate_ipv6_suffix(suffix)
        if not valid:
            return jsonify({'success': False, 'error': error}), 400
        
        # 校验手动IPv6
        valid, error = validate_ipv6_address(manual_ipv6)
        if not valid:
            return jsonify({'success': False, 'error': error}), 400
        
        # 校验手动IPv4
        valid, error = validate_ipv4_address(manual_ipv4)
        if not valid:
            return jsonify({'success': False, 'error': error}), 400
        
        # 清理后的数据
        clean_device = {
            **device,
            'device_id': device_id,
            'domain': domain,
            'suffix': suffix,
            'manual_ipv6': manual_ipv6,
            'manual_ipv4': manual_ipv4
        }
        
        device_id = db.add_device(clean_device)
        return jsonify({'success': True, 'id': device_id})


@api.route('/devices/<int:device_id>', methods=['PUT', 'DELETE'])
@require_private_ip
def device_detail(device_id):
    if request.method == 'PUT':
        device = request.json
        db.update_device(device_id, device)
        return jsonify({'success': True})
    else:
        # 删除设备前，先获取设备信息并删除对应的DNS记录
        devices = db.get_devices()
        device = next((d for d in devices if d['id'] == device_id), None)
        
        if device:
            # 尝试删除DNS记录
            config = db.get_dns_config()
            if config and config.get('access_key_id'):
                try:
                    from app.services.dns_provider.factory import DNSProviderFactory
                    dns = DNSProviderFactory.create(
                        config['provider'],
                        access_key_id=config['access_key_id'],
                        access_key_secret=config['access_key_secret']
                    )
                    
                    # 根据IP类型删除对应的DNS记录
                    ipv_type = device.get('ipv_type', 'ipv6')
                    domain = device['domain']
                    
                    if ipv_type in ['ipv4', 'both']:
                        print(f"[删除设备] 删除A记录: {domain}")
                        result = dns.delete_record(domain, 'A')
                        print(f"[删除设备] A记录删除结果: {result}")
                    
                    if ipv_type in ['ipv6', 'both']:
                        print(f"[删除设备] 删除AAAA记录: {domain}")
                        result = dns.delete_record(domain, 'AAAA')
                        print(f"[删除设备] AAAA记录删除结果: {result}")
                        
                except Exception as e:
                    print(f"[删除设备] 删除DNS记录时出错: {e}")
        
        # 从数据库删除设备
        db.delete_device(device_id)
        return jsonify({'success': True})


@api.route('/devices/<int:device_id>/update', methods=['POST'])
@require_private_ip
def update_device(device_id):
    ddns = refresh_ddns_service()
    if not ddns:
        return jsonify({'success': False, 'error': '请先配置DNS'})

    devices = db.get_devices()
    device = next((d for d in devices if d['id'] == device_id), None)

    if not device:
        return jsonify({'success': False, 'error': '设备不存在'})

    device_config = DeviceConfig(
        id=device['id'],
        device_id=device['device_id'],
        suffix=device.get('suffix', ''),
        domain=device['domain'],
        record_type=device['record_type'],
        enabled=bool(device['enabled']),
        ipv_type=device.get('ipv_type', 'ipv6'),
        ipv6_mode=device.get('ipv6_mode', 'auto'),
        manual_ipv6=device.get('manual_ipv6', ''),
        ipv4_mode=device.get('ipv4_mode', 'auto'),
        manual_ipv4=device.get('manual_ipv4', ''),
        last_ipv4=device.get('last_ipv4'),
        last_ipv6=device.get('last_ipv6'),
        source_type=device.get('source_type', 'auto'),
        source_domain=device.get('source_domain', '')
    )
    ddns.set_devices([device_config])
    # 使用 force_update 确保手动模式也能更新
    result = ddns.force_update()

    # 注意：日志已由 DDNS 服务自动记录，这里不需要重复记录

    return jsonify(result)


@api.route('/ddns/manual', methods=['POST'])
@require_private_ip
def manual_update():
    ddns = refresh_ddns_service()
    if not ddns:
        return jsonify({'success': False, 'error': '请先配置DNS'})

    data = request.json
    result = ddns.manual_update(data['domain'], data.get('ip', ''), data.get('record_type'))

    db.add_log({
        'device_id': 'manual',
        'domain': data['domain'],
        'old_ip': result.get('old_ip', ''),
        'new_ip': data.get('ip', ''),
        'record_type': result.get('record_type'),
        'status': 'success' if result.get('success') else 'failed',
        'error_msg': result.get('message', '')
    })

    return jsonify(result)


@api.route('/logs', methods=['GET', 'DELETE'])
@require_private_ip
def logs():
    if request.method == 'GET':
        limit = request.args.get('limit', 50, type=int)
        logs_list = db.get_logs(limit)
        return jsonify(logs_list)
    else:
        # 清除所有日志
        success = db.clear_logs()
        return jsonify({'success': success})


@api.route('/update/now', methods=['POST'])
@require_private_ip
def update_now():
    """立即更新全部 - 强制更新所有设备（包括手动模式）"""
    ddns = refresh_ddns_service()
    if not ddns:
        return jsonify({'success': False, 'error': '请先配置DNS'})

    result = ddns.force_update()
    
    # 注意：日志已由 DDNS 服务自动记录，这里不需要重复记录

    return jsonify(result)


@api.route('/ip/config', methods=['GET', 'POST'])
@require_private_ip
def ip_config():
    if request.method == 'GET':
        config = db.get_ip_config()
        return jsonify(config or {})
    else:
        config = request.json
        db.save_ip_config(config)
        return jsonify({'success': True})


@api.route('/settings', methods=['GET', 'POST'])
def settings():
    """获取或保存系统设置
    
    安全逻辑：
    - GET: 所有人都可以获取基本状态（是否开启公网访问）
    - POST: 开启公网访问 - 无限制（允许从公网开启）
           关闭公网访问 - 需要内网IP、白名单IP或已登录
           修改其他设置 - 需要内网IP或已登录
    """
    from app.utils.security import check_public_access, get_access_info, can_modify_public_access
    
    access_info = get_access_info()
    
    if request.method == 'GET':
        ip_config = db.get_ip_config() or {}
        allow_public = db.get_app_config('allow_public_access')
        ip_whitelist = db.get_app_config('ip_whitelist') or ''
        
        response_data = {
            'allow_public_access': allow_public == '1' or allow_public == 'true',
            'ip_whitelist': ip_whitelist,
            'client_ip': access_info['client_ip'],
            'is_private': access_info['is_private'],
            'is_logged_in': access_info['is_logged_in'],
            'can_modify': access_info['can_modify']
        }
        
        # 只有在允许访问的情况下才返回敏感配置
        if access_info['can_access']:
            response_data['update_interval'] = ip_config.get('update_interval', 180)
        
        return jsonify(response_data)
    else:
        config = request.json
        allow_public_access = config.get('allow_public_access')
        ip_whitelist = config.get('ip_whitelist')
        update_interval = config.get('update_interval')
        
        # 处理公网访问设置
        if allow_public_access is not None:
            if not allow_public_access:
                if not can_modify_public_access():
                    logger.warning(f"[设置] 拒绝关闭公网访问: {access_info['client_ip']}, 权限不足")
                    return jsonify({
                        'success': False,
                        'message': '关闭公网访问需要内网IP、白名单IP或已登录账号'
                    }), 403
                logger.info(f"[设置] 公网访问已关闭: {access_info['client_ip']}")
            else:
                logger.info(f"[设置] 公网访问已开启: {access_info['client_ip']}")
            db.set_app_config('allow_public_access', '1' if allow_public_access else '0')
        
        if ip_whitelist is not None:
            if not can_modify_public_access():
                logger.warning(f"[设置] 拒绝修改IP白名单: {access_info['client_ip']}, 权限不足")
                return jsonify({
                    'success': False,
                    'message': '修改IP白名单需要内网IP、白名单IP或已登录账号'
                }), 403
            logger.info(f"[设置] IP白名单已更新: {ip_whitelist}")
            db.set_app_config('ip_whitelist', ip_whitelist)
        
        if access_info['can_access'] and update_interval is not None:
            ip_config = db.get_ip_config() or {}
            ip_config['update_interval'] = update_interval
            db.save_ip_config(ip_config)
            logger.info(f"[设置] 更新间隔已修改: {update_interval}秒")
        
        return jsonify({'success': True})


@api.route('/notifications', methods=['GET', 'POST'])
@require_private_ip
def notifications():
    if request.method == 'GET':
        notifications_list = db.get_notifications()
        return jsonify(notifications_list)
    else:
        notification = request.json
        db.save_notification(notification)
        return jsonify({'success': True})


@api.route('/notifications/<int:notification_id>', methods=['DELETE'])
@require_private_ip
def notification_detail(notification_id):
    db.delete_notification(notification_id)
    return jsonify({'success': True})


@api.route('/test/notify', methods=['POST'])
@require_private_ip
def test_notify():
    notifier = NotificationManager()
    notifier.add_notifier(type('TestNotifier', (), {
        'send': lambda self, title, content: True
    })())

    context = NotifyContext(
        ipv4_addr='192.168.1.1',
        ipv4_result='测试',
        ipv4_domains='test.com',
        ipv6_addr='::1',
        ipv6_result='测试',
        ipv6_domains='test.com'
    )

    result = notifier.notify(context)
    return jsonify({'success': True, 'results': result})
