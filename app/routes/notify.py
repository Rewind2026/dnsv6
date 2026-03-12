from flask import Blueprint, request, jsonify
from app.models import Database
from app.services.notifier import ServerChanNotifier
from datetime import datetime

notify_api = Blueprint('notify', __name__, url_prefix='/api/notify')
db = Database()


@notify_api.route('/config', methods=['GET', 'POST'])
def notification_config():
    """获取或保存通知配置"""
    if request.method == 'GET':
        config = db.get_notification_config()
        if config:
            # 转换整数为布尔值，确保前端正确显示
            config['enabled'] = bool(config.get('enabled', 0))
            config['notify_on_success'] = bool(config.get('notify_on_success', 1))
            config['notify_on_failure'] = bool(config.get('notify_on_failure', 1))
            # 不返回敏感信息，但标记是否已配置
            full_config = db.get_notification_config()
            config['has_send_key'] = bool(full_config.get('send_key'))
            # 清空敏感字段
            config['send_key'] = ''
        return jsonify(config or {'enabled': False, 'notifier_type': 'serverchan', 'notify_on_success': True, 'notify_on_failure': True})
    else:
        new_config = request.json
        # 获取现有配置，合并敏感信息
        existing = db.get_notification_config() or {}
        
        # 如果新配置中的敏感字段为空，但已有配置，保留原有值
        if not new_config.get('send_key') and existing.get('send_key'):
            new_config['send_key'] = existing['send_key']
            
        db.save_notification_config(new_config)
        return jsonify({'success': True})


@notify_api.route('/test', methods=['POST'])
def test_notification():
    """测试通知 - 使用前端传来的配置或数据库配置"""
    data = request.json or {}
    
    # 优先使用前端传来的配置，否则使用数据库配置
    if data.get('enabled') is not None:
        config = data
    else:
        config = db.get_notification_config()
    
    if not config or not config.get('enabled'):
        return jsonify({'success': False, 'message': '通知未启用'})
    
    notifier_type = config.get('notifier_type', 'serverchan')
    
    try:
        if notifier_type == 'serverchan':
            send_key = config.get('send_key', '')
            if not send_key:
                return jsonify({'success': False, 'message': 'SendKey 未配置'})
            notifier = ServerChanNotifier(send_key)
            success = notifier.send('DDNS 测试通知', '这是一条测试消息')
            if success:
                return jsonify({'success': True, 'message': 'Server酱 通知发送成功'})
            return jsonify({'success': False, 'message': 'Server酱 通知发送失败'})
        else:
            return jsonify({'success': False, 'message': '未知的通知类型'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


def send_notification(ipv4: str = None, ipv6: str = None, 
                      ipv4_success: bool = True, ipv6_success: bool = True,
                      updated_domains: list = None,
                      update_details: list = None):
    """发送通知（被DDNS服务调用）
    
    Args:
        ipv4: 当前IPv4地址
        ipv6: 当前IPv6地址
        ipv4_success: IPv4更新是否成功
        ipv6_success: IPv6更新是否成功
        updated_domains: 更新的域名列表
        update_details: 详细更新信息列表，每项包含 device, domain, ip, old_ip, record_type
    """
    config = db.get_notification_config()
    if not config or not config.get('enabled'):
        return
    
    # 检查是否需要通知
    has_updates = update_details and len(update_details) > 0
    has_failures = not ipv4_success or not ipv6_success
    
    if not has_updates and not has_failures:
        # 没有更新且没有失败，不发送通知
        return
    
    if has_updates and not has_failures and not config.get('notify_on_success'):
        # 有更新但用户不需要成功通知
        return
    
    if has_failures and not config.get('notify_on_failure'):
        # 有失败但用户不需要失败通知
        return
    
    notifier_type = config.get('notifier_type', 'serverchan')
    
    # 构建消息内容
    if has_failures:
        title = "❌ DDNS 同步异常"
    else:
        title = "✅ DDNS 同步完成"
    
    content_parts = []
    content_parts.append(f"同步时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    content_parts.append("")
    
    # 添加详细更新信息
    if update_details:
        content_parts.append("📋 解析记录变更:")
        for i, detail in enumerate(update_details[:5], 1):  # 最多显示5条
            device = detail.get('device', '未知')
            domain = detail.get('domain', '未知')
            ip = detail.get('ip', '-')
            old_ip = detail.get('old_ip', '-')
            record_type = detail.get('record_type', 'A')
            
            content_parts.append(f"\n{i}. {domain}")
            content_parts.append(f"   记录类型: {record_type}")
            content_parts.append(f"   原地址: {old_ip}")
            content_parts.append(f"   新地址: {ip}")
        
        if len(update_details) > 5:
            content_parts.append(f"\n... 还有 {len(update_details) - 5} 个域名已同步")
    
    # 添加当前公网IP
    content_parts.append("")
    content_parts.append("🌐 当前公网地址:")
    if ipv4:
        content_parts.append(f"   IPv4: {ipv4}")
    if ipv6:
        content_parts.append(f"   IPv6: {ipv6}")
    
    content = "\n".join(content_parts)
    
    try:
        if notifier_type == 'serverchan' and config.get('send_key'):
            notifier = ServerChanNotifier(config['send_key'])
            notifier.send(title, content)
    except Exception:
        pass
