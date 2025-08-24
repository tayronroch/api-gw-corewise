# settings.py (excerto)
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from core.utils import ALLOWED_HOSTS

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=BASE_DIR / '.env')

# Tornar o pacote 'mpls_analyzer' importável diretamente
# Aponta para src/modules/mpls_analyzer para evitar namespace package ambíguo

# Security settings
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-default-secret-key-change-this')
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

INSTALLED_APPS = [
    # apps django
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # third party apps
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "drf_spectacular",  # OpenAPI/Swagger documentation
    "corsheaders",
    "axes",            # django-axes para rate limit/bloqueio de login
    "django_otp",      # django-otp para MFA
    "django_filters",
    # apps do projeto
    "core",            # Sistema global de logs e auditoria
    "modules.topology",
    "modules.networking",      # App para funcionalidades L2VPN/BGP/OSPF baseadas no l2vpn-master
    # Sistema MPLS Analyzer integrado
    "modules.mpls_analyzer",
]
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",    # Mover CORS para o topo
    "core.middleware.CorrelationIdMiddleware",  # Correlation Id
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    # "django.middleware.csrf.CsrfViewMiddleware",  # Temporariamente desabilitado para debug
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    # "axes.middleware.AxesMiddleware",   # Temporariamente desabilitado para debug
    "core.middleware.SecurityMiddleware",    # Middleware de segurança global
    "core.middleware.GlobalAuditMiddleware",  # Middleware de auditoria global
]
# AUTHENTICATION_BACKENDS - LDAP comentado para desenvolvimento
AUTHENTICATION_BACKENDS = [
    # "django_auth_ldap.backend.LDAPBackend",   # Autenticação LDAP - comentado para dev
    "django.contrib.auth.backends.ModelBackend",
]
# Configuração do django-axes - desabilitado em desenvolvimento
AXES_ENABLED = not DEBUG  # Desabilitar em desenvolvimento
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = 1  # 1 hora bloqueado após 5 falhas
AXES_LOCKOUT_TEMPLATE = 'axes/lockout.html'  # Template customizado para bloqueio
AXES_RESET_ON_SUCCESS = True
AXES_ONLY_USER_FAILURES = True
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True
AXES_USE_USER_AGENT = True
# Configurações de segurança - ajustadas para desenvolvimento
SESSION_COOKIE_SECURE = not DEBUG  # False em desenvolvimento
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax' if DEBUG else 'Strict'  # Lax em desenvolvimento
CSRF_COOKIE_SECURE = not DEBUG  # False em desenvolvimento
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3003",  # Adicionar a porta que o frontend está usando
    "http://127.0.0.1:3003",
]

# Desabilitar verificação CSRF para desenvolvimento
if DEBUG:
    CSRF_COOKIE_HTTPONLY = False
    CSRF_USE_SESSIONS = False

# Headers de segurança - apenas em produção
if not DEBUG:
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
# Headers CSP via django-csp se desejar

# Database Configuration (multi-DB)
# default: DB do core (SQLite em dev via USE_SQLITE=true, senão PostgreSQL)
if os.environ.get('USE_SQLITE', 'False').lower() == 'true':
    default_db = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
        'OPTIONS': {'timeout': 20},
    }
else:
    default_db = {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('POSTGRES_DB', 'corewiseengnir'),
        'USER': os.environ.get('POSTGRES_USER', 'admin'),
        'PASSWORD': os.environ.get('POSTGRES_PASSWORD', 'admin'),
        'HOST': os.environ.get('POSTGRES_HOST', 'localhost'),
        'PORT': os.environ.get('POSTGRES_PORT', '5432'),
    }

DATABASES = {
    'default': default_db,
    # Banco dedicado do MPLS Analyzer (bundled SQLite)
    'mpls': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'mpls_db.sqlite3',
        'OPTIONS': {'timeout': 20},
    },
}

# Comando padrão para coleta de configuração DMOS em JSON
# Pode ser sobrescrito via variável de ambiente DMOS_JSON_COMMAND
DMOS_JSON_COMMAND = os.environ.get('DMOS_JSON_COMMAND', 'show running-config json')

# Router para enviar consultas do app 'mpls_analyzer' ao DB 'mpls'
DATABASE_ROUTERS = [
    'core.db_router.MPLSRouter',
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Configurações REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour'
    },
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

# JWT Settings
from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': os.environ.get('SECRET_KEY', 'your-secret-key'),
    'AUTH_HEADER_TYPES': ('Bearer',),
}

# CORS settings para desenvolvimento
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    "http://localhost:3003",  # Porta que o frontend está usando
    "http://127.0.0.1:3003",
    "http://localhost:5173",  # Vite development server
    "http://127.0.0.1:5173",  # Vite development server
    "http://172.16.200.159:3001",
    "http://172.20.0.1:3001",
    "http://172.16.200.159:3003",
    "http://172.20.0.1:3003",
]

# Additional CORS settings for geospatial API
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = DEBUG  # Allow all origins in debug mode
CORS_ALLOWED_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]
CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = Path(__file__).resolve().parent.parent / 'staticfiles'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = Path(__file__).resolve().parent.parent / 'media'

# URL Configuration
ROOT_URLCONF = 'config.urls'

# Wsgi Application
WSGI_APPLICATION = 'config.wsgi.application'

# drf-spectacular settings
SPECTACULAR_SETTINGS = {
    'TITLE': 'CoreWise Engineering API',
    'DESCRIPTION': 'API completa para gerenciamento de infraestrutura de rede, topologia e engenharia de sistemas',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'SCHEMA_PATH_PREFIX': '/api/',
    'COMPONENT_SPLIT_REQUEST': True,
    'COMPONENT_NO_READ_ONLY_REQUIRED': True,
    'AUTHENTICATION_WHITELIST': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'SECURITY': [
        {
            'type': 'http',
            'scheme': 'bearer',
            'bearerFormat': 'JWT',
        },
        {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
        }
    ],
    'TAGS': [
        {'name': 'authentication', 'description': 'Operações de autenticação e autorização'},
        {'name': 'users', 'description': 'Gerenciamento de usuários'},
        {'name': 'topology', 'description': 'Topologia de rede e dispositivos'},
        {'name': 'engineering', 'description': 'Operações de engenharia'},
        {'name': 'security', 'description': 'Segurança e monitoramento'},
        {'name': 'mpls', 'description': 'Sistema MPLS Analyzer - Análise de configurações MPLS'},
        {'name': 'mpls-search', 'description': 'Busca inteligente MPLS'},
        {'name': 'mpls-reports', 'description': 'Relatórios MPLS'},
        {'name': 'mpls-admin', 'description': 'Administração MPLS'},
        {'name': 'audit', 'description': 'Sistema Global de Auditoria - Logs, segurança e monitoramento'},
        {'name': 'audit-logs', 'description': 'Logs de auditoria de todas as ações do sistema'},
        {'name': 'audit-security', 'description': 'Configurações e dashboard de segurança'},
        {'name': 'audit-monitoring', 'description': 'Monitoramento e health checks do sistema'},
    ],
    'EXTERNAL_DOCS': {
        'description': 'Documentação completa do CoreWise',
        'url': 'https://github.com/your-org/CoreWise',
    },
    'CONTACT': {
        'name': 'CoreWise Team',
        'email': 'support@corewise.com',
    },
    'LICENSE': {
        'name': 'MIT',
        'url': 'https://opensource.org/licenses/MIT',
    },
}
