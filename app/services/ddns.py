from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import sys
import os
import logging
import time
from datetime import datetime, timedelta

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 创建logger
logger = logging.getLogger('ddns_scheduler')

# 导入重试工具
from app.utils.retry import retry_dns_update


@dataclass
class DeviceConfig:
    device_id: str
    suffix: str
    domain: str
    record_type: str
    enabled: bool = True
    ipv_type: str = 'ipv6'
    ipv6_mode: str = 'auto'  # 'auto' 或 'manual'
    manual_ipv6: str = ''    # 手动指定的完整IPv6
    ipv4_mode: str = 'auto'  # 'auto' 或 'manual'
    manual_ipv4: str = ''    # 手动指定的完整IPv4
    id: int = None           # 数据库设备 ID
    last_ipv4: str = None   # 上次更新的 IPv4
    last_ipv6: str = None   # 上次更新的 IPv6
    source_type: str = 'auto'  # 'auto' 或 'domain'
    source_domain: str = ''      # 数据源域名（当 source_type 为 'domain' 时使用）


class DDNSService:
    # IP频繁跳变保护配置
    IP_CHANGE_WINDOW_MINUTES = 5  # 检测窗口：5分钟
    IP_CHANGE_THRESHOLD = 3       # 阈值：5分钟内变化超过3次
    IP_CHANGE_COOLDOWN_MINUTES = 15  # 冷却时间：15分钟
    # 数据库备份配置
    BACKUP_INTERVAL_DAYS = 7      # 每7天备份一次
    BACKUP_KEEP_COUNT = 10        # 保留最近10个备份
    
    def __init__(self, dns_provider, ip_detector, db=None):
        self.dns = dns_provider
        self.detector = ip_detector
        self.db = db
        self.devices: List[DeviceConfig] = []
        # 强制同步间隔（24小时）
        self.full_sync_interval = timedelta(hours=24)
        # 记录上次完整同步时间（从数据库加载，确保重启后仍然有效）
        self._load_last_full_sync_time()
        # IP变化历史记录（用于防封禁保护）
        self.ip_change_history: List[datetime] = []
        self.ip_change_cooldown_until: Optional[datetime] = None
        # 数据库备份记录（从数据库加载，确保重启后仍然有效）
        self._load_last_backup_time()
    
    def _load_last_full_sync_time(self):
        """从数据库加载上次强制同步时间"""
        if self.db:
            try:
                last_sync_str = self.db.get_app_config('last_full_sync_time')
                if last_sync_str:
                    self.last_full_sync = datetime.fromisoformat(last_sync_str)
                else:
                    self.last_full_sync = datetime.now() - timedelta(hours=25)
            except Exception as e:
                logger.warning(f"[强制同步] 加载上次同步时间失败: {e}")
                self.last_full_sync = datetime.now() - timedelta(hours=25)
        else:
            self.last_full_sync = datetime.now() - timedelta(hours=25)

    def _save_last_full_sync_time(self):
        """保存上次强制同步时间到数据库"""
        if self.db:
            try:
                self.db.set_app_config('last_full_sync_time', self.last_full_sync.isoformat())
            except Exception as e:
                logger.warning(f"[强制同步] 保存同步时间失败: {e}")

    def _should_full_sync(self) -> bool:
        """检查是否需要进行24小时强制同步"""
        return datetime.now() - self.last_full_sync >= self.full_sync_interval

    def _update_full_sync_time(self):
        """更新上次完整同步时间"""
        self.last_full_sync = datetime.now()
        self._save_last_full_sync_time()
        logger.info("[强制同步] 更新完整同步时间戳")

    def _load_last_backup_time(self):
        """从数据库加载上次备份时间"""
        self.backup_interval = timedelta(days=self.BACKUP_INTERVAL_DAYS)
        if self.db:
            try:
                last_backup_str = self.db.get_app_config('last_backup_time')
                if last_backup_str:
                    self.last_backup = datetime.fromisoformat(last_backup_str)
                else:
                    # 首次运行，设置为8天前确保会触发备份
                    self.last_backup = datetime.now() - timedelta(days=8)
            except Exception as e:
                logger.warning(f"[数据库备份] 加载上次备份时间失败: {e}")
                self.last_backup = datetime.now() - timedelta(days=8)
        else:
            self.last_backup = datetime.now() - timedelta(days=8)

    def _save_last_backup_time(self):
        """保存上次备份时间到数据库"""
        if self.db:
            try:
                self.db.set_app_config('last_backup_time', self.last_backup.isoformat())
            except Exception as e:
                logger.warning(f"[数据库备份] 保存备份时间失败: {e}")

    def _should_backup(self) -> bool:
        """检查是否需要进行数据库备份"""
        return datetime.now() - self.last_backup >= self.backup_interval

    def _do_backup(self):
        """执行数据库备份"""
        if not self.db:
            return
        try:
            backup_path = self.db.backup_database()
            if backup_path:
                self.last_backup = datetime.now()
                self._save_last_backup_time()  # 持久化备份时间
                logger.info(f"[数据库备份] 备份完成: {backup_path}")
                # 清理旧备份
                deleted = self.db.cleanup_old_backups(keep_count=self.BACKUP_KEEP_COUNT)
                if deleted > 0:
                    logger.info(f"[数据库备份] 已清理 {deleted} 个旧备份")
        except Exception as e:
            logger.error(f"[数据库备份] 备份失败: {e}")
    
    def _load_devices_from_db(self) -> List[DeviceConfig]:
        """从数据库重新加载设备配置（无状态设计）"""
        if not self.db:
            return []
        
        devices_data = self.db.get_devices()
        devices = []
        for d in devices_data:
            device = DeviceConfig(
                device_id=d['device_id'],
                suffix=d.get('suffix', ''),
                domain=d['domain'],
                record_type=d.get('record_type', 'AAAA'),
                enabled=bool(d.get('enabled', 1)),
                ipv_type=d.get('ipv_type', 'ipv6'),
                ipv6_mode=d.get('ipv6_mode', 'auto'),
                manual_ipv6=d.get('manual_ipv6', ''),
                ipv4_mode=d.get('ipv4_mode', 'auto'),
                manual_ipv4=d.get('manual_ipv4', ''),
                id=d.get('id'),
                last_ipv4=d.get('last_ipv4'),
                last_ipv6=d.get('last_ipv6'),
                source_type=d.get('source_type', 'auto'),
                source_domain=d.get('source_domain', '')
            )
            devices.append(device)
        
        logger.info(f"[配置加载] 从数据库加载了 {len(devices)} 个设备")
        return devices
    
    @retry_dns_update(max_retries=3)
    def _update_dns_with_retry(self, domain: str, record_type: str, value: str) -> dict:
        """
        带重试机制的DNS更新
        使用指数退避：5s, 15s, 30s
        """
        return self.dns.update_record(domain=domain, record_type=record_type, value=value)

    def _record_ip_change(self):
        """记录一次IP变化事件"""
        now = datetime.now()
        self.ip_change_history.append(now)
        # 清理过期的历史记录（超过窗口期的）
        cutoff = now - timedelta(minutes=self.IP_CHANGE_WINDOW_MINUTES)
        self.ip_change_history = [t for t in self.ip_change_history if t > cutoff]
        logger.debug(f"[IP变化] 记录IP变化，当前窗口内变化次数: {len(self.ip_change_history)}")

    def _is_ip_change_rate_limited(self) -> bool:
        """检查是否处于IP频繁跳变保护冷却期

        Returns:
            True: 处于冷却期，应暂停更新
            False: 正常，可以更新
        """
        now = datetime.now()

        # 检查是否在冷却期内
        if self.ip_change_cooldown_until and now < self.ip_change_cooldown_until:
            remaining = (self.ip_change_cooldown_until - now).seconds // 60
            logger.warning(f"[IP保护] 处于冷却期，还剩 {remaining} 分钟，暂停更新以防止DNS服务商封禁")
            return True

        # 清理过期的历史记录
        cutoff = now - timedelta(minutes=self.IP_CHANGE_WINDOW_MINUTES)
        self.ip_change_history = [t for t in self.ip_change_history if t > cutoff]

        # 检查是否超过阈值
        if len(self.ip_change_history) >= self.IP_CHANGE_THRESHOLD:
            # 触发冷却期
            self.ip_change_cooldown_until = now + timedelta(minutes=self.IP_CHANGE_COOLDOWN_MINUTES)
            logger.error(
                f"[IP保护] 检测到IP频繁跳变！{self.IP_CHANGE_WINDOW_MINUTES}分钟内变化 {len(self.ip_change_history)} 次，"
                f"触发 {self.IP_CHANGE_COOLDOWN_MINUTES} 分钟冷却期"
            )
            return True

        return False

    def _get_last_ipv4(self) -> Optional[str]:
        """从数据库获取上次保存的IPv4"""
        if self.db:
            return self.db.get_ip_state('last_ipv4')
        return None

    def _get_last_ipv6_prefix(self) -> Optional[str]:
        """从数据库获取上次保存的IPv6前缀"""
        if self.db:
            return self.db.get_ip_state('last_ipv6_prefix')
        return None

    def _save_last_ipv4(self, ipv4: str):
        """保存当前IPv4到数据库"""
        if self.db and ipv4:
            self.db.save_ip_state('last_ipv4', ipv4)

    def _save_last_ipv6_prefix(self, prefix: str):
        """保存当前IPv6前缀到数据库"""
        if self.db and prefix:
            self.db.save_ip_state('last_ipv6_prefix', prefix)
    
    def _update_device_ip_state(self, device: DeviceConfig, ipv4: str = None, ipv6: str = None):
        """更新设备的 IP 状态到数据库"""
        if self.db and device.id:
            self.db.update_device_ip(device.id, ipv4=ipv4, ipv6=ipv6)

    def set_devices(self, devices: List[DeviceConfig]):
        self.devices = devices

    def check_and_update(self, force: bool = False) -> Dict[str, Any]:
        """
        检查IP变化并更新DDNS记录
        
        每个设备根据自己的配置独立检测和更新：
        - 根据每个设备的 ipv_type 设置决定检测和更新哪种 IP
        - 根据每个设备的 ipv4_mode/ipv6_mode 决定自动还是手动
        - 根据每个设备的 last_ipv4/last_ipv6 判断是否需要更新
        
        改进：
        - 每次从数据库重新加载设备配置（无状态设计）
        - 24小时强制同步机制
        - DNS更新失败时指数退避重试
        
        Args:
            force: 是否强制更新（手动触发时使用）
        """
        trigger_type = "手动触发" if force else "自动检测"
        logger.info(f"[{trigger_type}] 开始检测 IP 变化")
        
        # 检查是否需要24小时强制同步
        should_full_sync = self._should_full_sync()
        if should_full_sync:
            logger.info("[强制同步] 距离上次完整同步已超过24小时，执行强制同步")
            force = True  # 强制同步时，相当于force模式
            self._update_full_sync_time()
        
        # 无状态设计：每次从数据库重新加载设备配置
        self.devices = self._load_devices_from_db()
        if not self.devices:
            logger.warning("[配置加载] 数据库中没有配置任何设备")
            return {
                'success': True,
                'ipv4': None,
                'ipv6': None,
                'ipv4_changed': False,
                'ipv6_prefix_changed': False,
                'results': {
                    'ipv4': {'updated': [], 'failed': [], 'skipped': [], 'unchanged': []},
                    'ipv6': {'updated': [], 'failed': [], 'skipped': [], 'unchanged': []}
                }
            }
        
        results = {
            'ipv4': {'updated': [], 'failed': [], 'skipped': [], 'unchanged': []},
            'ipv6': {'updated': [], 'failed': [], 'skipped': [], 'unchanged': []}
        }

        # 获取当前公网IP（只获取一次，供自动模式设备使用）
        current_ipv4 = self.detector.get_public_ipv4()
        current_ipv6_prefix, current_ipv6, local_ipv6_list = self.detector.get_ipv6_info()
        
        logger.info(f"[IP检测] 当前公网 IPv4: {current_ipv4 or '未获取到'}")
        logger.info(f"[IP检测] 当前公网 IPv6: {current_ipv6 or '未获取到'}")
        logger.info(f"[IP检测] 当前 IPv6 前缀: {current_ipv6_prefix or '未获取到'}")

        # 检查IP是否发生变化（用于防封禁保护）
        last_ipv4 = self._get_last_ipv4()
        last_ipv6_prefix = self._get_last_ipv6_prefix()
        ipv4_changed = current_ipv4 and current_ipv4 != last_ipv4
        ipv6_prefix_changed = current_ipv6_prefix and current_ipv6_prefix != last_ipv6_prefix
        
        # IP频繁跳变保护（防封禁）
        if not force and (ipv4_changed or ipv6_prefix_changed):
            if self._is_ip_change_rate_limited():
                logger.warning("[IP保护] 检测到IP频繁跳变，暂停本次更新")
                return {
                    'success': False,
                    'ipv4': current_ipv4,
                    'ipv6': current_ipv6,
                    'ipv4_changed': ipv4_changed,
                    'ipv6_prefix_changed': ipv6_prefix_changed,
                    'results': results,
                    'rate_limited': True,
                    'message': 'IP频繁跳变保护已触发，暂停更新'
                }
            # 记录IP变化
            self._record_ip_change()

        for device in self.devices:
            logger.info(f"[设备] {device.device_id} (域名: {device.domain}, 类型: {device.ipv_type})")
            
            # 未启用的设备只有在 force=True（手动更新）时才处理
            if not device.enabled and not force:
                logger.info(f"[设备] {device.device_id} 未启用，跳过")
                results[device.ipv_type]['skipped'].append({
                    'device': device.device_id,
                    'domain': device.domain,
                    'reason': 'disabled'
                })
                continue

            # 根据数据源类型获取当前IP
            device_ipv4 = None
            device_ipv6 = None
            
            if device.source_type == 'domain' and device.source_domain:
                # 从域名解析IP
                logger.info(f"[数据源] 从域名解析: {device.source_domain}")
                device_ipv4 = self.detector.get_ip_from_domain(device.source_domain, 'ipv4')
                device_ipv6 = self.detector.get_ip_from_domain(device.source_domain, 'ipv6')
                logger.info(f"[数据源] 解析 IPv4: {device_ipv4 or '未解析到'}")
                logger.info(f"[数据源] 解析 IPv6: {device_ipv6 or '未解析到'}")
            else:
                # 使用自动检测的公网IP
                device_ipv4 = current_ipv4
                device_ipv6 = current_ipv6
            
            device_ipv6_prefix = self.detector.extract_ipv6_prefix(device_ipv6) if device_ipv6 else None

            # 获取设备上次的 IP 状态（从设备配置中获取）
            last_ipv4 = device.last_ipv4
            last_ipv6 = device.last_ipv6
            last_ipv6_prefix = self.detector.extract_ipv6_prefix(last_ipv6) if last_ipv6 else None

            logger.info(f"[IP对比] IPv4: 上次={last_ipv4 or '无'}, 当前={device_ipv4 or '无'}")
            logger.info(f"[IP对比] IPv6: 上次={last_ipv6 or '无'}, 当前前缀={device_ipv6_prefix or '无'}")

            # 检测设备 IP 是否变化
            ipv4_changed = device_ipv4 and device_ipv4 != last_ipv4
            ipv6_prefix_changed = device_ipv6_prefix and device_ipv6_prefix != last_ipv6_prefix
            
            ipv4_changed_str = '是' if ipv4_changed else '否'
            ipv6_changed_str = '是' if ipv6_prefix_changed else '否'
            logger.info(f"[变化检测] IPv4变化={ipv4_changed_str}, IPv6前缀变化={ipv6_changed_str}")

            # 处理 IPv4（根据 ipv_type 决定是否处理）
            if device.ipv_type in ['ipv4', 'both']:
                ipv4_to_use = None
                should_update = False
                
                if device.ipv4_mode == 'manual':
                    ipv4_to_use = device.manual_ipv4
                    should_update = force and bool(ipv4_to_use)
                    mode_desc = '手动模式'
                else:
                    ipv4_to_use = device_ipv4
                    should_update = (force or ipv4_changed) and bool(ipv4_to_use)
                    mode_desc = '自动模式'
                
                logger.info(f"[IPv4] 模式={mode_desc}, 准备更新={should_update}, IP={ipv4_to_use or '无'}")

                if should_update and ipv4_to_use:
                    logger.info(f"[IPv4] 正在更新 A 记录...")
                    try:
                        # 使用带重试机制的DNS更新
                        result = self._update_dns_with_retry(
                            domain=device.domain,
                            record_type='A',
                            value=ipv4_to_use
                        )
                        if result.get('unchanged'):
                            logger.info(f"[IPv4] IP未变化，无需更新")
                            results['ipv4']['unchanged'].append({
                                'device': device.device_id,
                                'domain': device.domain,
                                'ip': ipv4_to_use,
                                'reason': result.get('message', 'IP未变化')
                            })
                        elif result.get('success'):
                            logger.info(f"[IPv4] 更新成功: {result.get('old_ip') or '无'} -> {ipv4_to_use}")
                            results['ipv4']['updated'].append({
                                'device': device.device_id,
                                'domain': device.domain,
                                'ip': ipv4_to_use,
                                'old_ip': result.get('old_ip'),
                                'mode': mode_desc,
                                'trigger': 'force' if force else 'auto'
                            })
                            self._update_device_ip_state(device, ipv4=ipv4_to_use)
                            logger.info(f"[IPv4] IP状态已保存到数据库")
                        else:
                            logger.error(f"[IPv4] 更新失败: {result.get('message')}")
                            results['ipv4']['failed'].append({
                                'device': device.device_id,
                                'domain': device.domain,
                                'error': result.get('message', '更新失败')
                            })
                    except Exception as e:
                        # 重试后仍然失败
                        logger.error(f"[IPv4] 更新失败（已重试3次）: {str(e)}")
                        results['ipv4']['failed'].append({
                            'device': device.device_id,
                            'domain': device.domain,
                            'error': f'更新失败（已重试3次）: {str(e)}'
                        })
                elif device.ipv4_mode == 'auto' and not ipv4_changed and not force:
                    logger.info(f"[IPv4] IP未变化，跳过更新")
                    results['ipv4']['unchanged'].append({
                        'device': device.device_id,
                        'domain': device.domain,
                        'ip': current_ipv4,
                        'reason': 'IP未变化'
                    })

            # 处理 IPv6（根据 ipv_type 决定是否处理）
            if device.ipv_type in ['ipv6', 'both']:
                ipv6_to_use = None
                should_update = False
                
                if device.ipv6_mode == 'manual':
                    ipv6_to_use = device.manual_ipv6
                    should_update = force and bool(ipv6_to_use)
                    mode_desc = '手动模式'
                else:
                    mode_desc = '自动模式'
                    if device_ipv6_prefix and device.suffix:
                        ipv6_to_use = self.detector.combine_ipv6_address(device_ipv6_prefix, device.suffix)
                        logger.info(f"[IPv6] 拼接后缀: {device_ipv6_prefix} + {device.suffix} = {ipv6_to_use}")
                    elif device_ipv6 and not device.suffix:
                        ipv6_to_use = device_ipv6
                    should_update = (force or ipv6_prefix_changed) and bool(ipv6_to_use)
                
                logger.info(f"[IPv6] 模式={mode_desc}, 准备更新={should_update}, IP={ipv6_to_use or '无'}")

                if should_update and ipv6_to_use:
                    logger.info(f"[IPv6] 正在更新 AAAA 记录...")
                    try:
                        # 使用带重试机制的DNS更新
                        result = self._update_dns_with_retry(
                            domain=device.domain,
                            record_type='AAAA',
                            value=ipv6_to_use
                        )
                        if result.get('unchanged'):
                            logger.info(f"[IPv6] IP未变化，无需更新")
                            results['ipv6']['unchanged'].append({
                                'device': device.device_id,
                                'domain': device.domain,
                                'ip': ipv6_to_use,
                                'reason': result.get('message', 'IP未变化')
                            })
                        elif result.get('success'):
                            logger.info(f"[IPv6] 更新成功: {result.get('old_ip') or '无'} -> {ipv6_to_use}")
                            results['ipv6']['updated'].append({
                                'device': device.device_id,
                                'domain': device.domain,
                                'ip': ipv6_to_use,
                                'old_ip': result.get('old_ip'),
                                'mode': mode_desc,
                                'trigger': 'force' if force else 'auto'
                            })
                            self._update_device_ip_state(device, ipv6=ipv6_to_use)
                            logger.info(f"[IPv6] IP状态已保存到数据库")
                        else:
                            logger.error(f"[IPv6] 更新失败: {result.get('message')}")
                            results['ipv6']['failed'].append({
                                'device': device.device_id,
                                'domain': device.domain,
                                'error': result.get('message', '更新失败')
                            })
                    except Exception as e:
                        # 重试后仍然失败
                        logger.error(f"[IPv6] 更新失败（已重试3次）: {str(e)}")
                        results['ipv6']['failed'].append({
                            'device': device.device_id,
                            'domain': device.domain,
                            'error': f'更新失败（已重试3次）: {str(e)}'
                        })
                elif device.ipv6_mode == 'auto' and not ipv6_prefix_changed and not force:
                    logger.info(f"[IPv6] 前缀未变化，跳过更新")
                    results['ipv6']['unchanged'].append({
                        'device': device.device_id,
                        'domain': device.domain,
                        'ip': device_ipv6_prefix + '::/64' if device_ipv6_prefix else '',
                        'reason': '前缀未变化'
                    })

        all_success = (
            len(results['ipv4']['failed']) == 0 and
            len(results['ipv6']['failed']) == 0
        )
        
        # 记录日志到数据库
        try:
            from app.models import Database
            db = Database()
            for r_type in ['ipv4', 'ipv6']:
                # 记录成功的更新
                for item in results[r_type]['updated']:
                    db.add_log({
                        'device_id': item['device'],
                        'domain': item['domain'],
                        'old_ip': item.get('old_ip', ''),
                        'new_ip': item['ip'],
                        'record_type': 'A' if r_type == 'ipv4' else 'AAAA',
                        'status': 'success'
                    })
                # 记录失败的更新
                for item in results[r_type]['failed']:
                    db.add_log({
                        'device_id': item['device'],
                        'domain': item['domain'],
                        'old_ip': '',
                        'new_ip': '',
                        'record_type': 'A' if r_type == 'ipv4' else 'AAAA',
                        'status': 'failed'
                    })
        except Exception as e:
            logger.error(f"记录日志到数据库失败: {e}")
        
        # 发送通知
        try:
            from routes.notify import send_notification
            
            # 收集详细更新信息
            update_details = []
            for r_type in ['ipv4', 'ipv6']:
                for item in results[r_type]['updated']:
                    update_details.append({
                        'device': item['device'],
                        'domain': item['domain'],
                        'ip': item['ip'],
                        'old_ip': item.get('old_ip', '-'),
                        'record_type': 'A' if r_type == 'ipv4' else 'AAAA'
                    })
            
            ipv4_success = len(results['ipv4']['failed']) == 0
            ipv6_success = len(results['ipv6']['failed']) == 0
            
            # 只在有更新或失败时发送通知
            if update_details or not all_success:
                send_notification(
                    ipv4=current_ipv4 if current_ipv4 else None,
                    ipv6=current_ipv6 if current_ipv6 else None,
                    ipv4_success=ipv4_success,
                    ipv6_success=ipv6_success,
                    update_details=update_details if update_details else None
                )
        except Exception:
            pass

        # 数据库自动瘦身：清理30天前的旧日志
        try:
            if self.db:
                self.db.cleanup_old_logs(days=30)
        except Exception as e:
            logger.warning(f"[日志清理] 清理旧日志时出错: {e}")

        # 数据库定期备份（每7天）
        try:
            if self._should_backup():
                logger.info("[数据库备份] 触发定期备份")
                self._do_backup()
        except Exception as e:
            logger.error(f"[数据库备份] 备份触发失败: {e}")

        return {
            'success': all_success,
            'ipv4': current_ipv4,
            'ipv6': current_ipv6,
            'ipv4_changed': ipv4_changed,
            'ipv6_prefix_changed': ipv6_prefix_changed,
            'results': results
        }

    def auto_update(self) -> Dict[str, Any]:
        """定时自动更新（只更新自动模式的设备）"""
        return self.check_and_update(force=False)

    def force_update(self) -> Dict[str, Any]:
        """强制更新所有设备（手动触发）"""
        return self.check_and_update(force=True)

    def manual_update(self, domain: str, ip_address: str,
                     record_type: str = None) -> Dict[str, Any]:
        """手动更新指定域名的DNS记录（带重试机制）"""
        if record_type is None:
            record_type = 'AAAA' if ':' in ip_address else 'A'

        try:
            # 使用带重试机制的DNS更新
            result = self._update_dns_with_retry(
                domain=domain,
                record_type=record_type,
                value=ip_address
            )

            return {
                'success': result.get('success', False),
                'domain': domain,
                'ip': ip_address,
                'record_type': record_type,
                'old_ip': result.get('old_ip'),
                'message': result.get('message', '')
            }
        except Exception as e:
            # 重试后仍然失败
            logger.error(f"[手动更新] 更新失败（已重试3次）: {str(e)}")
            return {
                'success': False,
                'domain': domain,
                'ip': ip_address,
                'record_type': record_type,
                'old_ip': None,
                'message': f'更新失败（已重试3次）: {str(e)}'
            }
