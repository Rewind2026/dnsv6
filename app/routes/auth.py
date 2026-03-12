from flask import Blueprint, request, jsonify, session
from app.models import Database
import json
import hashlib
import time
import threading
from datetime import datetime, timedelta

auth = Blueprint('auth', __name__, url_prefix='/api/auth')
db = Database()

# 登录失败记录 {ip: {'count': 0, 'last_attempt': timestamp, 'locked_until': timestamp}}
login_attempts = {}
login_attempts_lock = threading.Lock()

# 配置
MAX_LOGIN_ATTEMPTS = 5  # 最大尝试次数
LOCKOUT_DURATION = 900  # 锁定时间（15分钟）


def get_client_ip():
    """获取客户端IP地址"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr


def is_ip_locked(ip):
    """检查IP是否被锁定"""
    with login_attempts_lock:
        if ip in login_attempts:
            lock_info = login_attempts[ip]
            if lock_info.get('locked_until'):
                if datetime.now() < lock_info['locked_until']:
                    remaining = (lock_info['locked_until'] - datetime.now()).seconds
                    return True, remaining
                else:
                    # 锁定已过期，重置
                    del login_attempts[ip]
        return False, 0


def record_login_attempt(ip, success=False):
    """记录登录尝试"""
    now = datetime.now()
    
    with login_attempts_lock:
        if ip not in login_attempts:
            login_attempts[ip] = {'count': 0, 'last_attempt': now}
        
        if success:
            # 登录成功，清除记录
            if ip in login_attempts:
                del login_attempts[ip]
        else:
            # 登录失败
            login_attempts[ip]['count'] += 1
            login_attempts[ip]['last_attempt'] = now
            
            # 检查是否需要锁定
            if login_attempts[ip]['count'] >= MAX_LOGIN_ATTEMPTS:
                lock_until = now + timedelta(seconds=LOCKOUT_DURATION)
                login_attempts[ip]['locked_until'] = lock_until
                return True, LOCKOUT_DURATION
        
        return False, 0


def log_login_event(username, success, ip, message=''):
    """记录登录日志到文件"""
    import logging
    login_logger = logging.getLogger('ddns_login')
    
    # 如果logger没有配置，创建一个文件handler
    if not login_logger.handlers:
        from logging.handlers import TimedRotatingFileHandler
        import os
        
        log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        today = datetime.now().strftime('%Y-%m-%d')
        log_file = os.path.join(log_dir, f"login-{today}.log")
        
        handler = TimedRotatingFileHandler(
            log_file,
            when='midnight',
            interval=1,
            backupCount=30,
            encoding='utf-8'
        )
        handler.suffix = '%Y-%m-%d.log'
        
        class LoginJsonFormatter(logging.Formatter):
            def format(self, record):
                log_data = {
                    '时间': datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S'),
                    '级别': record.levelname,
                    '内容': record.getMessage()
                }
                return json.dumps(log_data, ensure_ascii=False)
        
        handler.setFormatter(LoginJsonFormatter())
        login_logger.addHandler(handler)
        login_logger.setLevel(logging.INFO)
    
    status = '成功' if success else '失败'
    log_msg = f"[登录{status}] 用户: {username}, IP: {ip}"
    if message:
        log_msg += f", 详情: {message}"
    
    if success:
        login_logger.info(log_msg)
    else:
        login_logger.warning(log_msg)


@auth.route('/check', methods=['GET'])
def check_auth():
    """检查是否已登录"""
    if 'user_id' in session:
        return jsonify({'logged_in': True, 'username': session.get('username')})
    return jsonify({'logged_in': False})


@auth.route('/login', methods=['POST'])
def login():
    """登录"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    ip = get_client_ip()
    
    # 检查IP是否被锁定
    locked, remaining = is_ip_locked(ip)
    if locked:
        log_login_event(username, False, ip, f'IP被锁定，还剩{remaining}秒')
        return jsonify({
            'success': False, 
            'message': f'登录失败次数过多，请{remaining // 60}分钟后再试'
        })
    
    if not username or not password:
        return jsonify({'success': False, 'message': '请输入用户名和密码'})
    
    # 如果没有用户，直接创建一个管理员
    if not db.has_users():
        db.create_user(username, password)
        session.permanent = True
        session['user_id'] = 1
        session['username'] = username
        log_login_event(username, True, ip, '首次登录，创建管理员')
        return jsonify({'success': True, 'message': '登录成功（已创建管理员）'})
    
    # 检查用户是否存在
    user = db.get_user(username)
    if not user:
        record_login_attempt(ip, False)
        log_login_event(username, False, ip, '用户名不存在')
        return jsonify({'success': False, 'message': '用户名不存在'})
    
    # 验证密码
    if db.verify_password(username, password):
        record_login_attempt(ip, True)
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = username
        log_login_event(username, True, ip)
        return jsonify({'success': True, 'message': '登录成功'})
    
    # 密码错误
    should_lock, lock_time = record_login_attempt(ip, False)
    remaining_attempts = MAX_LOGIN_ATTEMPTS - login_attempts[ip]['count']
    
    if should_lock:
        log_login_event(username, False, ip, f'密码错误，IP已被锁定15分钟')
        return jsonify({
            'success': False, 
            'message': f'登录失败次数过多，IP已被锁定15分钟'
        })
    else:
        log_login_event(username, False, ip, f'密码错误，还剩{remaining_attempts}次机会')
        return jsonify({
            'success': False, 
            'message': f'密码错误，还剩{remaining_attempts}次机会'
        })


@auth.route('/logout', methods=['POST'])
def logout():
    """登出"""
    username = session.get('username', 'unknown')
    ip = get_client_ip()
    log_login_event(username, True, ip, '用户登出')
    session.clear()
    return jsonify({'success': True})


@auth.route('/register', methods=['POST'])
def register():
    """注册新用户（如果已有管理员则需要验证）"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    ip = get_client_ip()
    
    if not username or not password:
        return jsonify({'success': False, 'message': '请输入用户名和密码'})
    
    if len(password) < 6:
        return jsonify({'success': False, 'message': '密码长度至少6位'})
    
    if db.create_user(username, password):
        log_login_event(username, True, ip, '注册新用户')
        return jsonify({'success': True, 'message': '注册成功'})
    else:
        log_login_event(username, False, ip, '注册失败，用户名已存在')
        return jsonify({'success': False, 'message': '用户名已存在'})


@auth.route('/change-password', methods=['POST'])
def change_password():
    """修改密码"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登录'})
    
    data = request.json
    username = session.get('username')
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    ip = get_client_ip()
    
    if not old_password or not new_password:
        return jsonify({'success': False, 'message': '请输入旧密码和新密码'})
    
    if len(new_password) < 6:
        return jsonify({'success': False, 'message': '新密码长度至少6位'})
    
    if not db.verify_password(username, old_password):
        log_login_event(username, False, ip, '修改密码失败，旧密码错误')
        return jsonify({'success': False, 'message': '旧密码错误'})
    
    # 更新密码
    if db.update_password(username, new_password):
        log_login_event(username, True, ip, '修改密码成功')
        return jsonify({'success': True, 'message': '密码修改成功'})
    else:
        log_login_event(username, False, ip, '修改密码失败，数据库错误')
        return jsonify({'success': False, 'message': '密码修改失败，请稍后重试'})
