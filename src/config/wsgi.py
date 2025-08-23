import os

from django.core.wsgi import get_wsgi_application

# Set default Django settings module for WSGI
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

application = get_wsgi_application()
