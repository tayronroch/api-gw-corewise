import logging
from django.conf import settings
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

def get_logger(name="core"):
    logger = logging.getLogger(name)
    if not logger.handlers:
        log_dir = Path(getattr(settings, 'LOG_DIR', 'logs'))
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / "app.log"
        handler = logging.FileHandler(log_file, encoding="utf-8")
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s: Usuário %(username)s %(operation)s "
            "na cidade %(cidade)s (log_id: %(log_id)s) [in %(pathname)s:%(lineno)d]"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'troque-esta-chave')
DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'
ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 3600
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

LOG_DIR = os.path.join(BASE_DIR, 'logs')
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(LOG_DIR, 'app.log'),
            'formatter': 'verbose',
        },
    },
    'formatters': {
        'verbose': {
            'format': '%(asctime)s %(levelname)s %(message)s'
        },
    },
    'root': {
        'handlers': ['file'],
        'level': 'INFO',
    },
} 