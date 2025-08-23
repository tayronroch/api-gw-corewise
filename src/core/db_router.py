class MPLSRouter:
    """Database router to direct mpls_analyzer app to the dedicated SQLite DB.

    - Reads/writes for models with app_label 'mpls_analyzer' go to alias 'mpls'.
    - Disallow migrations for this app to preserve the bundled schema.
    """

    app_label = 'modules.mpls_analyzer'
    db_alias = 'mpls'

    def db_for_read(self, model, **hints):
        if model._meta.app_label == self.app_label:
            return self.db_alias
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label == self.app_label:
            return self.db_alias
        return None

    def allow_relation(self, obj1, obj2, **hints):
        # Permite relações envolvendo modelos do app; Django não cria FKs cross-DB
        if obj1._meta.app_label == self.app_label or obj2._meta.app_label == self.app_label:
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        # Impede migrações para o app mpls_analyzer para preservar o schema original
        if app_label == self.app_label:
            return False
        return None
