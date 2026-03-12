import sqlite3
import json
import os
from typing import Optional, List, Dict, Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Database:
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(BASE_DIR, "data/ddns.db")
        self.db_path = db_path
        self.init_db()

    def _get_conn(self):
        """获取数据库连接（添加超时和线程检查）"""
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=10  # 10秒超时，避免database is locked
        )
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def init_db(self):
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=10
        )
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT UNIQUE NOT NULL,
                suffix TEXT,
                domain TEXT NOT NULL,
                record_type TEXT DEFAULT 'AAAA',
                enabled INTEGER DEFAULT 1,
                ipv_type TEXT DEFAULT 'ipv6',
                ipv6_mode TEXT DEFAULT 'auto',
                manual_ipv6 TEXT,
                ipv4_mode TEXT DEFAULT 'auto',
                manual_ipv4 TEXT,
                last_ipv4 TEXT,
                last_ipv6 TEXT,
                source_type TEXT DEFAULT 'auto',
                source_domain TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 迁移：为旧表添加新字段
        try:
            cursor.execute("ALTER TABLE devices ADD COLUMN ipv6_mode TEXT DEFAULT 'auto'")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE devices ADD COLUMN manual_ipv6 TEXT")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE devices ADD COLUMN ipv4_mode TEXT DEFAULT 'auto'")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE devices ADD COLUMN manual_ipv4 TEXT")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE devices ADD COLUMN last_ipv4 TEXT")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE devices ADD COLUMN last_ipv6 TEXT")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE devices ADD COLUMN source_type TEXT DEFAULT 'auto'")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE devices ADD COLUMN source_domain TEXT")
        except:
            pass

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_config (
                id INTEGER PRIMARY KEY,
                provider TEXT DEFAULT 'aliyun',
                access_key_id TEXT,
                access_key_secret TEXT,
                domain_name TEXT,
                ttl INTEGER DEFAULT 600,
                updated_at TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS update_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT,
                domain TEXT,
                old_ip TEXT,
                new_ip TEXT,
                record_type TEXT,
                status TEXT,
                error_msg TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                config TEXT,
                notify_on_success INTEGER DEFAULT 1,
                notify_on_failure INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS app_config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notification_config (
                id INTEGER PRIMARY KEY,
                notifier_type TEXT DEFAULT 'serverchan',
                enabled INTEGER DEFAULT 0,
                send_key TEXT,
                notify_on_success INTEGER DEFAULT 1,
                notify_on_failure INTEGER DEFAULT 1,
                updated_at TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_config (
                id INTEGER PRIMARY KEY,
                ipv4_method TEXT DEFAULT 'api',
                ipv4_url TEXT DEFAULT 'https://api.ipify.org',
                ipv4_interface TEXT,
                ipv4_command TEXT,
                ipv6_method TEXT DEFAULT 'api',
                ipv6_url TEXT DEFAULT 'https://api64.ipify.org',
                ipv6_interface TEXT,
                ipv6_command TEXT,
                update_interval INTEGER DEFAULT 300
            )
        ''')

        # 保存上次检测的IP状态，用于判断IP是否变化
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_state (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        conn.close()

    def get_dns_config(self) -> Optional[Dict]:
        from app.utils.crypto import decrypt_text
        conn = self._get_conn()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM dns_config LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        if row:
            config = dict(row)
            # 解密敏感字段
            config['access_key_id'] = decrypt_text(config.get('access_key_id', ''))
            config['access_key_secret'] = decrypt_text(config.get('access_key_secret', ''))
            return config
        return None

    def save_dns_config(self, config: Dict):
        from app.utils.crypto import encrypt_text
        conn = self._get_conn()
        cursor = conn.cursor()
        # 加密敏感字段
        encrypted_key_id = encrypt_text(config.get('access_key_id', ''))
        encrypted_key_secret = encrypt_text(config.get('access_key_secret', ''))
        cursor.execute('''
            INSERT OR REPLACE INTO dns_config
            (id, provider, access_key_id, access_key_secret, domain_name, ttl, updated_at)
            VALUES (1, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (config.get('provider'), encrypted_key_id,
              encrypted_key_secret, config.get('domain_name'),
              config.get('ttl', 600)))
        conn.commit()
        conn.close()

    def get_devices(self) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices ORDER BY id")
        rows = cursor.fetchall()
        devices = [dict(row) for row in rows]
        
        # 为每个设备添加状态（基于最近24小时的更新日志）
        for device in devices:
            cursor.execute('''
                SELECT status, created_at 
                FROM update_logs 
                WHERE device_id = ? 
                ORDER BY created_at DESC 
                LIMIT 1
            ''', (device['device_id'],))
            last_log = cursor.fetchone()
            
            if not device.get('enabled', 1):
                device['status'] = 'disabled'
            elif last_log:
                status = last_log['status']
                if status == 'success':
                    device['status'] = 'online'
                else:
                    device['status'] = 'offline'
            else:
                # 没有日志记录，根据是否有IP判断
                if device.get('last_ipv6') or device.get('last_ipv4'):
                    device['status'] = 'online'
                else:
                    device['status'] = 'offline'
        
        conn.close()
        return devices

    def add_device(self, device: Dict) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO devices (device_id, suffix, domain, record_type, enabled, ipv_type,
                                ipv6_mode, manual_ipv6, ipv4_mode, manual_ipv4,
                                source_type, source_domain)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (device.get('device_id'), device.get('suffix'), device.get('domain'),
              device.get('record_type', 'AAAA'), device.get('enabled', 1),
              device.get('ipv_type', 'ipv6'), device.get('ipv6_mode', 'auto'),
              device.get('manual_ipv6', ''), device.get('ipv4_mode', 'auto'),
              device.get('manual_ipv4', ''), device.get('source_type', 'auto'),
              device.get('source_domain', '')))
        conn.commit()
        device_id = cursor.lastrowid
        conn.close()
        return device_id

    def update_device(self, device_id: int, device: Dict):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        fields = []
        values = []
        for key in ['device_id', 'suffix', 'domain', 'record_type', 'enabled', 'ipv_type',
                    'ipv6_mode', 'manual_ipv6', 'ipv4_mode', 'manual_ipv4', 'last_ipv4', 'last_ipv6',
                    'source_type', 'source_domain']:
            if key in device:
                fields.append(f"{key} = ?")
                values.append(device[key])
        values.append(device_id)
        cursor.execute(f"UPDATE devices SET {', '.join(fields)} WHERE id = ?", values)
        conn.commit()
        conn.close()
    
    def update_device_ip(self, device_id: int, ipv4: str = None, ipv6: str = None):
        """更新设备的最后 IP 状态"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        fields = []
        values = []
        if ipv4 is not None:
            fields.append("last_ipv4 = ?")
            values.append(ipv4)
        if ipv6 is not None:
            fields.append("last_ipv6 = ?")
            values.append(ipv6)
        if fields:
            values.append(device_id)
            cursor.execute(f"UPDATE devices SET {', '.join(fields)} WHERE id = ?", values)
            conn.commit()
        conn.close()

    def delete_device(self, device_id: int):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        conn.commit()
        conn.close()

    def add_log(self, log: Dict):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO update_logs (device_id, domain, old_ip, new_ip, record_type, status, error_msg)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (log.get('device_id'), log.get('domain'), log.get('old_ip'),
              log.get('new_ip'), log.get('record_type'), log.get('status'),
              log.get('error_msg')))
        conn.commit()
        conn.close()

    def get_logs(self, limit: int = 50) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM update_logs ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def clear_logs(self) -> bool:
        """清除所有日志记录"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM update_logs")
            conn.commit()
            deleted_count = cursor.rowcount
            conn.close()
            print(f"[清除日志] 已清除 {deleted_count} 条日志记录")
            return True
        except Exception as e:
            print(f"[清除日志] 清除日志失败: {e}")
            return False

    def cleanup_old_logs(self, days: int = 30) -> int:
        """清理指定天数之前的旧日志，防止数据库膨胀

        Args:
            days: 保留多少天内的日志，默认30天

        Returns:
            删除的记录数量
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            # 使用参数化查询防止SQL注入
            cursor.execute(
                "DELETE FROM update_logs WHERE created_at < datetime('now', '-' || ? || ' days')",
                (days,)
            )
            conn.commit()
            deleted_count = cursor.rowcount
            conn.close()
            if deleted_count > 0:
                print(f"[日志清理] 已清理 {deleted_count} 条 {days} 天前的旧日志")
            return deleted_count
        except Exception as e:
            print(f"[日志清理] 清理旧日志失败: {e}")
            return 0

    def backup_database(self, backup_dir: str = None) -> str:
        """备份数据库到指定目录

        Args:
            backup_dir: 备份目录，默认为 data/backups

        Returns:
            备份文件路径
        """
        from datetime import datetime

        if backup_dir is None:
            backup_dir = os.path.join(BASE_DIR, "data/backups")

        # 确保备份目录存在
        os.makedirs(backup_dir, exist_ok=True)

        # 生成备份文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"ddns_backup_{timestamp}.db"
        backup_path = os.path.join(backup_dir, backup_filename)

        try:
            # 使用SQLite的在线备份功能（Python 3.7+）
            # 这种方式不会锁定数据库，可以在线备份
            source_conn = sqlite3.connect(self.db_path)
            backup_conn = sqlite3.connect(backup_path)
            with backup_conn:
                source_conn.backup(backup_conn)
            source_conn.close()
            backup_conn.close()

            print(f"[数据库备份] 已创建备份: {backup_filename}")
            return backup_path
        except Exception as e:
            print(f"[数据库备份] 备份失败: {e}")
            return None

    def cleanup_old_backups(self, backup_dir: str = None, keep_count: int = 10) -> int:
        """清理旧的数据库备份，只保留最近N个

        Args:
            backup_dir: 备份目录，默认为 data/backups
            keep_count: 保留的备份数量，默认10个

        Returns:
            删除的备份文件数量
        """
        import glob

        if backup_dir is None:
            backup_dir = os.path.join(BASE_DIR, "data/backups")

        if not os.path.exists(backup_dir):
            return 0

        try:
            # 获取所有备份文件，按修改时间排序
            backup_files = glob.glob(os.path.join(backup_dir, "ddns_backup_*.db"))
            backup_files.sort(key=os.path.getmtime, reverse=True)

            # 删除旧备份
            deleted = 0
            for old_file in backup_files[keep_count:]:
                os.remove(old_file)
                deleted += 1
                print(f"[备份清理] 已删除旧备份: {os.path.basename(old_file)}")

            return deleted
        except Exception as e:
            print(f"[备份清理] 清理失败: {e}")
            return 0

    def get_app_config(self, key: str) -> Optional[str]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM app_config WHERE key = ?", (key,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def set_app_config(self, key: str, value: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO app_config (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
        conn.close()

    def get_ip_config(self) -> Optional[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ip_config LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def save_ip_config(self, config: Dict):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # 先删除旧记录再插入，避免列数不匹配问题
        cursor.execute("DELETE FROM ip_config WHERE id = 1")
        cursor.execute('''
            INSERT INTO ip_config
            (id, ipv4_method, ipv4_url, ipv4_interface, ipv4_command,
             ipv6_method, ipv6_url, ipv6_interface, ipv6_command, update_interval)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (config.get('ipv4_method'), config.get('ipv4_url'),
              config.get('ipv4_interface'), config.get('ipv4_command'),
              config.get('ipv6_method'), config.get('ipv6_url'),
              config.get('ipv6_interface'), config.get('ipv6_command'),
              config.get('update_interval', 180)))
        conn.commit()
        conn.close()

    # 用户认证相关
    def get_user(self, username: str) -> Optional[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def create_user(self, username: str, password: str) -> bool:
        import hashlib
        hashed = hashlib.sha256(password.encode()).hexdigest()
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
            conn.commit()
            conn.close()
            return True
        except:
            return False

    def verify_password(self, username: str, password: str) -> bool:
        import hashlib
        hashed = hashlib.sha256(password.encode()).hexdigest()
        user = self.get_user(username)
        return user and user['password'] == hashed

    def update_password(self, username: str, new_password: str) -> bool:
        """更新用户密码"""
        import hashlib
        hashed = hashlib.sha256(new_password.encode()).hexdigest()
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, username))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[更新密码] 失败: {e}")
            return False

    def has_users(self) -> bool:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    # 通知配置相关
    def get_notification_config(self) -> Optional[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM notification_config LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def save_notification_config(self, config: Dict):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # 先删除旧记录再插入，避免列数不匹配问题
        cursor.execute("DELETE FROM notification_config WHERE id = 1")
        cursor.execute('''
            INSERT INTO notification_config
            (id, notifier_type, enabled, send_key, 
             notify_on_success, notify_on_failure, updated_at)
            VALUES (1, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (config.get('notifier_type', 'serverchan'),
              1 if config.get('enabled') else 0,
              config.get('send_key', ''),
              1 if config.get('notify_on_success') else 0,
              1 if config.get('notify_on_failure') else 0))
        conn.commit()
        conn.close()

    def get_notifications(self) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM notifications WHERE enabled = 1")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def save_notification(self, notification: Dict):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO notifications
            (id, type, enabled, config, notify_on_success, notify_on_failure)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (notification.get('id'), notification.get('type'),
              notification.get('enabled', 1), notification.get('config'),
              notification.get('notify_on_success', 1),
              notification.get('notify_on_failure', 1)))
        conn.commit()
        conn.close()

    def delete_notification(self, notification_id: int):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM notifications WHERE id = ?", (notification_id,))
        conn.commit()
        conn.close()

    # IP 状态相关（用于判断IP是否变化）
    def get_ip_state(self, key: str) -> Optional[str]:
        """获取上次保存的IP状态"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM ip_state WHERE key = ?", (key,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def save_ip_state(self, key: str, value: str):
        """保存当前IP状态"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO ip_state (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
        ''', (key, value))
        conn.commit()
        conn.close()
