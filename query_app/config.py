import os


VERSION = '0.2'
PROJECT_NAME = 'SecuritySitesQuery'
MODULE_NAME = 'query_app'

# 项目根目录
ROOT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 项目子目录
MODULE_PATH = os.path.join(ROOT_PATH, MODULE_NAME)
DATA_PATH = os.path.join(MODULE_PATH, 'data')
TEMP_PATH = os.path.join(MODULE_PATH, 'temp')


UPDATE_INTERVAL = 86400.0  # 升级间隔: 一天
DEBUG = False

if not os.path.exists(TEMP_PATH):
    try:
        os.makedirs(TEMP_PATH)
    except Exception:
        print('无法建立temp目录! 请手动建立query_app/temp')
        raise IOError

# 搜索参数
CONFIG = {
    'keyword': None,
    'mode': None,
    'site': None,
    'update': None,
    'output': None,
    'path': None,
    'name': None
}

# 输出文件日志,只保存一天的记录
LOGGING = {
    'version': 1,
    'formatters': {
        'file': {
            'format': '%(asctime)s - %(levelname)s - %(module)s - %(message)s',
        },
    },
    'handlers': {
        'file': {
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'formatter': 'file',
            'level': 'DEBUG' if DEBUG else 'INFO',
            'when': 'midnight',
            'filename': DATA_PATH + '/ssquery.log',
            'backupCount': 0,
            'encoding': None,
        },
    },
    'loggers': {
        'main': {
            'handlers': ['file'],
            'level': 'DEBUG' if DEBUG else 'INFO',
        },
    }
}
