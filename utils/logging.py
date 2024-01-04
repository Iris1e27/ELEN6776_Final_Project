import logging
import functools

# 配置日志
logging.basicConfig(filename='app.log', filemode='w', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

def log_decorator(func):
    """日志装饰器"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            logging.info(f"Function {func.__name__} started with args: {args} and kwargs: {kwargs}")
            result = func(*args, **kwargs)
            logging.info(f"Function {func.__name__} ended successfully")
            return result
        except Exception as e:
            logging.exception(f"Function {func.__name__} raised an exception: {e}")
            # 可以选择在这里重新抛出异常，或者返回某种错误表示
            raise 
    return wrapper