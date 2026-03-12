"""
重试工具模块 - 实现指数退避重试机制
"""
import time
import logging
from functools import wraps
from typing import Callable, Any, Optional

logger = logging.getLogger('ddns_scheduler')


def retry_with_backoff(
    max_retries: int = 3,
    delays: list = None,
    exceptions: tuple = (Exception,),
    on_retry: Optional[Callable] = None
):
    """
    指数退避重试装饰器
    
    Args:
        max_retries: 最大重试次数
        delays: 每次重试的延迟时间（秒），默认 [5, 15, 30]
        exceptions: 需要捕获的异常类型
        on_retry: 重试时的回调函数
    """
    if delays is None:
        delays = [5, 15, 30]  # 默认指数退避：5s, 15s, 30s
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt < max_retries - 1:
                        delay = delays[min(attempt, len(delays) - 1)]
                        logger.warning(
                            f"[{func.__name__}] 第{attempt + 1}次尝试失败: {str(e)}, "
                            f"{delay}秒后重试..."
                        )
                        
                        if on_retry:
                            try:
                                on_retry(attempt, e, delay)
                            except Exception:
                                pass
                        
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"[{func.__name__}] 所有{max_retries}次尝试均失败: {str(e)}"
                        )
            
            # 所有重试都失败，抛出最后一个异常
            raise last_exception
        
        return wrapper
    return decorator


def retry_dns_update(max_retries: int = 3):
    """
    DNS更新专用的重试装饰器
    使用指数退避：5s, 15s, 30s
    """
    return retry_with_backoff(
        max_retries=max_retries,
        delays=[5, 15, 30],
        exceptions=(Exception,)
    )
