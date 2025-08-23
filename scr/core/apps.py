from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'
    verbose_name = 'Core - Utilitários e Auditoria Global'
    
    def ready(self):
        """Importar signals quando a aplicação estiver pronta"""
        try:
            from . import signals  # noqa F401
        except ImportError:
            pass