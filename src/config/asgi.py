import os

from django.core.asgi import get_asgi_application

# Set default Django settings module for ASGI
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

application = get_asgi_application()
