import os
import sys
import time
import threading
import logging
import json
from datetime import datetime
from flask import Flask, jsonify
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
from apscheduler.executors.pool import ThreadPoolExecutor

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from app.models import Database


class JsonFormatter(logging.Formatter):
    """JSON日志格式器 - 简洁格式，只保留关键信息"""
    def format(self, record):
        log_data = {
            '时间': datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S'),
            '级别': record.levelname,
            '内容': record.getMessage()
        }
        if record.exc_info:
            log_data['异常'] = self.formatException(record.exc_info)
        return json.dumps(log_data, ensure_ascii=False)


def setup_logging():
    """配置调度器日志 - 只记录业务日志，过滤APScheduler内部日志"""
    from logging.handlers import TimedRotatingFileHandler, RotatingFileHandler
    
    log_dir = os.path.join(BASE_DIR, "data", "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    # 按天生成日志文件，格式：scheduler-2026-03-05.log
    from datetime import datetime
    today = datetime.now().strftime('%Y-%m-%d')
    log_file = os.path.join(log_dir, f"scheduler-{today}.log")
    
    # 按天轮转，保留30天
    file_handler = TimedRotatingFileHandler(
        log_file, 
        when='midnight', 
        interval=1, 
        backupCount=30,
        encoding='utf-8'
    )
    file_handler.suffix = '%Y-%m-%d.log'
    file_handler.setFormatter(JsonFormatter())
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    # 创建业务日志logger
    logger = logging.getLogger('ddns_scheduler')
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # 禁用APScheduler的默认日志
    logging.getLogger('apscheduler').setLevel(logging.WARNING)
    logging.getLogger('apscheduler.executors').setLevel(logging.WARNING)
    logging.getLogger('apscheduler.scheduler').setLevel(logging.WARNING)
    
    return logger


def create_app():
    app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))
    app.secret_key = os.urandom(24)
    
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = 900

    from app.routes.web import web
    from app.routes.api import api
    from app.routes.auth import auth
    from app.routes.notify import notify_api

    app.register_blueprint(web)
    app.register_blueprint(api)
    app.register_blueprint(auth)
    app.register_blueprint(notify_api)

    @app.route('/health')
    def health():
        return jsonify({'status': 'ok'})

    return app


logger = setup_logging()

executors = {
    'default': ThreadPoolExecutor(5)
}

job_defaults = {
    'coalesce': True,
    'max_instances': 1,
    'misfire_grace_time': 60
}

scheduler = BackgroundScheduler(
    timezone='Asia/Shanghai',
    executors=executors,
    job_defaults=job_defaults
)


def job_func(app):
    """定时更新任务"""
    logger.info("[调度任务] 开始执行DDNS更新...")
    try:
        with app.app_context():
            from app.routes.api import refresh_ddns_service, get_ddns_service
            refresh_ddns_service()
            ddns = get_ddns_service()
            if ddns:
                ddns.auto_update()
                logger.info("[调度任务] DDNS更新完成")
            else:
                logger.warning("[调度任务] DDNS服务未初始化")
    except Exception as e:
        logger.error(f"[调度任务] 执行失败: {e}", exc_info=True)


def job_executed(event):
    """任务执行完成回调"""
    if event.exception:
        logger.error(f"[调度任务] 执行异常: {event.exception}")
    else:
        logger.info(f"[调度任务] 执行成功")


def job_error(event):
    """任务执行错误回调"""
    logger.error(f"[调度任务] 任务ID {event.job_id} 执行失败: {event.exception}")


def run_scheduler(app):
    """启动调度器"""
    logger.info("[调度器] 正在启动APScheduler调度器...")
    scheduler.add_listener(job_executed, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)
    
    def get_interval():
        with app.app_context():
            db = Database()
            config = db.get_ip_config()
            return config.get('update_interval', 180) if config else 180

    interval_seconds = get_interval()
    
    scheduler.add_job(
        lambda: job_func(app),
        trigger=IntervalTrigger(seconds=interval_seconds),
        id='ddns_update',
        name='DDNS定时更新',
        replace_existing=True
    )
    logger.info(f"[调度器] 初始检测间隔: {interval_seconds}秒")
    logger.info(f"[调度器] 已添加定时任务: DDNS定时更新 (每{interval_seconds}秒执行一次)")
    
    scheduler.start()
    logger.info("[调度器] 调度器启动成功，开始运行")
    
    last_interval = interval_seconds
    while True:
        time.sleep(10)
        
        current_interval = get_interval()
        if current_interval != last_interval:
            logger.info(f"[调度器] 检测间隔已变更: {last_interval}秒 -> {current_interval}秒")
            scheduler.reschedule_job('ddns_update', trigger=IntervalTrigger(seconds=current_interval))
            last_interval = current_interval


def main():
    app = create_app()

    db_path = os.path.join(BASE_DIR, "data/ddns.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    # 检查是否在Flask reloader进程中运行
    # WERKZEUG_RUN_MAIN只在主进程中设置，reloader进程中不存在
    is_reloader = os.environ.get('WERKZEUG_RUN_MAIN') is not None
    is_main_process = not is_reloader
    
    # 只在主进程中启动调度器，避免debug模式下重复启动
    if is_main_process:
        scheduler_thread = threading.Thread(target=run_scheduler, args=(app,), daemon=True)
        scheduler_thread.start()
        logger.info("[主进程] 调度器线程已启动")
    else:
        logger.info("[Reloader进程] 跳过调度器启动")

    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)


if __name__ == '__main__':
    main()
