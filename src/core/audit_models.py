"""
Sistema Global de Logs e Auditoria CoreWise
Baseado no sistema robusto do MPLS Analyzer, adaptado para toda a aplicação
"""
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey


class GlobalAccessLog(models.Model):
    """Log de acesso global para toda a aplicação"""
    STATUS_CHOICES = [
        ('success', 'Sucesso'),
        ('failed', 'Falha'),
        ('logout', 'Logout'),
        ('locked', 'Conta Bloqueada'),
        ('mfa_required', 'MFA Necessário'),
        ('mfa_failed', 'MFA Falhou'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='global_access_logs')
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    session_key = models.CharField(max_length=40, blank=True)
    failure_reason = models.CharField(max_length=200, blank=True)
    app_name = models.CharField(max_length=50, blank=True, help_text="App onde ocorreu o acesso")
    endpoint = models.CharField(max_length=200, blank=True, help_text="Endpoint acessado")
    
    class Meta:
        verbose_name = "Log de Acesso Global"
        verbose_name_plural = "Logs de Acesso Global"
        ordering = ['-login_time']
        indexes = [
            models.Index(fields=['user', '-login_time']),
            models.Index(fields=['ip_address', '-login_time']),
            models.Index(fields=['status', '-login_time']),
            models.Index(fields=['app_name', '-login_time']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.get_status_display()} - {self.login_time.strftime('%Y-%m-%d %H:%M:%S')}"


class GlobalAuditLog(models.Model):
    """Log de auditoria global para todas as ações da aplicação"""
    ACTION_CHOICES = [
        # Ações de autenticação
        ('login', 'Login realizado'),
        ('logout', 'Logout realizado'),
        ('password_change', 'Senha alterada'),
        ('mfa_setup', 'MFA configurado'),
        ('mfa_disable', 'MFA desabilitado'),
        
        # Ações de busca
        ('search', 'Busca realizada'),
        ('advanced_search', 'Busca avançada'),
        ('filter_applied', 'Filtro aplicado'),
        
        # Ações de dados
        ('create', 'Registro criado'),
        ('update', 'Registro atualizado'),
        ('delete', 'Registro deletado'),
        ('bulk_update', 'Atualização em lote'),
        ('bulk_delete', 'Exclusão em lote'),
        
        # Ações de relatórios
        ('report_view', 'Relatório visualizado'),
        ('report_export', 'Relatório exportado'),
        ('dashboard_view', 'Dashboard visualizado'),
        
        # Ações de sistema
        ('system_backup', 'Backup do sistema'),
        ('system_restore', 'Restore do sistema'),
        ('system_maintenance', 'Manutenção do sistema'),
        ('config_change', 'Configuração alterada'),
        
        # Ações administrativas
        ('user_create', 'Usuário criado'),
        ('user_update', 'Usuário atualizado'),
        ('user_delete', 'Usuário removido'),
        ('user_lock', 'Usuário bloqueado'),
        ('user_unlock', 'Usuário desbloqueado'),
        ('permission_grant', 'Permissão concedida'),
        ('permission_revoke', 'Permissão revogada'),
        
        # Ações de segurança
        ('security_alert', 'Alerta de segurança'),
        ('suspicious_activity', 'Atividade suspeita'),
        ('access_denied', 'Acesso negado'),
        ('rate_limit_exceeded', 'Limite de taxa excedido'),
        
        # Ações específicas por módulo
        ('topology_view', 'Topologia visualizada'),
        ('topology_edit', 'Topologia editada'),
        ('equipment_connect', 'Equipamento conectado'),
        ('network_config', 'Configuração de rede'),
        ('mpls_analysis', 'Análise MPLS'),
        ('engineering_task', 'Tarefa de engenharia'),
    ]

    # Campos básicos
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='global_audit_logs')
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    description = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Informações de contexto
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    app_name = models.CharField(max_length=50, help_text="Nome do app Django")
    module_name = models.CharField(max_length=50, blank=True, help_text="Módulo específico (MPLS, Topology, etc)")
    endpoint = models.CharField(max_length=200, blank=True, help_text="URL/endpoint acessado")
    
    # Objeto relacionado (GenericForeignKey para qualquer modelo)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')
    
    # Dados específicos da ação
    search_query = models.TextField(blank=True, help_text="Query de busca realizada")
    export_format = models.CharField(max_length=20, blank=True, help_text="Formato de export (xlsx, csv, pdf)")
    results_count = models.PositiveIntegerField(null=True, blank=True, help_text="Quantidade de resultados")
    old_values = models.JSONField(default=dict, blank=True, help_text="Valores anteriores (para updates)")
    new_values = models.JSONField(default=dict, blank=True, help_text="Novos valores")
    additional_data = models.JSONField(default=dict, blank=True, help_text="Dados extras em JSON")
    
    # Campos de performance
    execution_time_ms = models.PositiveIntegerField(null=True, blank=True, help_text="Tempo de execução em ms")
    memory_usage_mb = models.FloatField(null=True, blank=True, help_text="Uso de memória em MB")
    
    # Status da ação
    success = models.BooleanField(default=True, help_text="Se a ação foi bem sucedida")
    error_message = models.TextField(blank=True, help_text="Mensagem de erro se houver")
    
    class Meta:
        verbose_name = "Log de Auditoria Global"
        verbose_name_plural = "Logs de Auditoria Global"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
            models.Index(fields=['app_name', 'module_name', '-timestamp']),
            models.Index(fields=['ip_address', '-timestamp']),
            models.Index(fields=['content_type', 'object_id']),
            models.Index(fields=['success', '-timestamp']),
        ]

    def __str__(self):
        module_info = f"[{self.module_name}] " if self.module_name else ""
        return f"{self.user.username} - {module_info}{self.get_action_display()} - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"

    @classmethod
    def log_action(cls, user, action, description, request=None, target_object=None, **kwargs):
        """Método helper para registrar ações de auditoria"""
        audit_data = {
            'user': user,
            'action': action,
            'description': description,
        }
        
        if request:
            audit_data.update({
                'ip_address': cls.get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'endpoint': request.path,
            })
        
        if target_object:
            audit_data.update({
                'content_object': target_object,
            })
        
        # Adicionar dados extras
        audit_data.update(kwargs)
        
        return cls.objects.create(**audit_data)
    
    @staticmethod
    def get_client_ip(request):
        """Obter IP real do cliente considerando proxies"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class GlobalSecuritySettings(models.Model):
    """Configurações globais de segurança para toda a aplicação"""
    
    # Configurações de tentativas de login
    max_login_attempts = models.PositiveIntegerField(
        default=5,
        help_text="Número máximo de tentativas de login antes do bloqueio"
    )
    lockout_duration_minutes = models.PositiveIntegerField(
        default=15,
        help_text="Duração do bloqueio em minutos após exceder tentativas"
    )
    
    # Configurações de sessão
    session_timeout_minutes = models.PositiveIntegerField(
        default=120,
        help_text="Tempo limite da sessão em minutos (0 = nunca expira)"
    )
    concurrent_sessions_limit = models.PositiveIntegerField(
        default=3,
        help_text="Número máximo de sessões simultâneas por usuário"
    )
    
    # Configurações de auditoria
    audit_retention_days = models.PositiveIntegerField(
        default=90,
        help_text="Quantos dias manter logs de auditoria (0 = manter sempre)"
    )
    access_log_retention_days = models.PositiveIntegerField(
        default=30,
        help_text="Quantos dias manter logs de acesso (0 = manter sempre)"
    )
    
    # Configurações de IP e geolocalização
    enable_ip_whitelist = models.BooleanField(
        default=False,
        help_text="Habilitar lista de IPs permitidos"
    )
    allowed_ips = models.TextField(
        blank=True,
        help_text="IPs permitidos (um por linha, suporta CIDR)"
    )
    enable_geo_blocking = models.BooleanField(
        default=False,
        help_text="Bloquear acessos de países específicos"
    )
    blocked_countries = models.TextField(
        blank=True,
        help_text="Códigos de países bloqueados (um por linha, formato ISO)"
    )
    
    # Configurações de senha
    password_min_length = models.PositiveIntegerField(
        default=8,
        help_text="Comprimento mínimo da senha"
    )
    password_require_uppercase = models.BooleanField(
        default=True,
        help_text="Exigir pelo menos uma letra maiúscula"
    )
    password_require_lowercase = models.BooleanField(
        default=True,
        help_text="Exigir pelo menos uma letra minúscula"
    )
    password_require_numbers = models.BooleanField(
        default=True,
        help_text="Exigir pelo menos um número"
    )
    password_require_symbols = models.BooleanField(
        default=False,
        help_text="Exigir pelo menos um símbolo especial"
    )
    password_history_count = models.PositiveIntegerField(
        default=5,
        help_text="Quantas senhas anteriores lembrar para evitar reuso"
    )
    
    # Configurações de MFA
    mfa_required_for_admin = models.BooleanField(
        default=True,
        help_text="MFA obrigatório para usuários administrativos"
    )
    mfa_required_for_all = models.BooleanField(
        default=False,
        help_text="MFA obrigatório para todos os usuários"
    )
    mfa_backup_codes_count = models.PositiveIntegerField(
        default=10,
        help_text="Número de códigos de backup MFA gerados"
    )
    
    # Configurações de rate limiting
    api_rate_limit_per_minute = models.PositiveIntegerField(
        default=100,
        help_text="Limite de requisições de API por minuto por usuário"
    )
    search_rate_limit_per_minute = models.PositiveIntegerField(
        default=30,
        help_text="Limite de buscas por minuto por usuário"
    )
    export_rate_limit_per_hour = models.PositiveIntegerField(
        default=10,
        help_text="Limite de exports por hora por usuário"
    )
    
    # Configurações de notificações
    notify_admin_on_failed_login = models.BooleanField(
        default=True,
        help_text="Notificar admin sobre falhas de login"
    )
    notify_admin_on_user_lockout = models.BooleanField(
        default=True,
        help_text="Notificar admin sobre bloqueios de usuário"
    )
    notify_admin_on_suspicious_activity = models.BooleanField(
        default=True,
        help_text="Notificar admin sobre atividade suspeita"
    )
    admin_notification_email = models.EmailField(
        blank=True,
        help_text="Email para notificações administrativas"
    )
    
    # Metadados
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        help_text="Usuário que fez a última alteração"
    )

    class Meta:
        verbose_name = "Configurações de Segurança Global"
        verbose_name_plural = "Configurações de Segurança Global"

    def __str__(self):
        return f"Configurações de Segurança Global - Atualizado em {self.updated_at.strftime('%d/%m/%Y %H:%M')}"

    @classmethod
    def get_settings(cls):
        """Retorna as configurações atuais ou cria padrões se não existir"""
        settings, created = cls.objects.get_or_create(
            id=1,  # Sempre usar ID 1 para singleton
            defaults={
                'max_login_attempts': 5,
                'lockout_duration_minutes': 15,
                'session_timeout_minutes': 120,
                'concurrent_sessions_limit': 3,
                'audit_retention_days': 90,
                'access_log_retention_days': 30,
                'password_min_length': 8,
                'password_require_uppercase': True,
                'password_require_lowercase': True,
                'password_require_numbers': True,
                'password_require_symbols': False,
                'password_history_count': 5,
                'mfa_required_for_admin': True,
                'api_rate_limit_per_minute': 100,
                'search_rate_limit_per_minute': 30,
                'export_rate_limit_per_hour': 10,
                'notify_admin_on_failed_login': True,
                'notify_admin_on_user_lockout': True,
                'notify_admin_on_suspicious_activity': True,
            }
        )
        return settings


class GlobalLoginAttempt(models.Model):
    """Registro global de tentativas de login para controle de segurança"""
    
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    success = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=200, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    app_name = models.CharField(max_length=50, blank=True, help_text="App onde ocorreu a tentativa")
    endpoint = models.CharField(max_length=200, blank=True, help_text="Endpoint de login")
    geolocation = models.JSONField(default=dict, blank=True, help_text="Dados de geolocalização do IP")
    
    class Meta:
        verbose_name = "Tentativa de Login Global"
        verbose_name_plural = "Tentativas de Login Global"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['username', 'ip_address', '-timestamp']),
            models.Index(fields=['ip_address', '-timestamp']),
            models.Index(fields=['success', '-timestamp']),
            models.Index(fields=['app_name', '-timestamp']),
        ]

    def __str__(self):
        status = "Sucesso" if self.success else "Falha"
        return f"{self.username} - {status} - {self.timestamp.strftime('%d/%m/%Y %H:%M:%S')}"

    @classmethod
    def is_ip_blocked(cls, ip_address):
        """Verifica se um IP está bloqueado por muitas tentativas"""
        settings = GlobalSecuritySettings.get_settings()
        
        # Calcula o período de verificação
        from datetime import timedelta
        check_period = timezone.now() - timedelta(minutes=settings.lockout_duration_minutes)
        
        # Conta tentativas falhadas no período
        failed_attempts = cls.objects.filter(
            ip_address=ip_address,
            success=False,
            timestamp__gte=check_period
        ).count()
        
        return failed_attempts >= settings.max_login_attempts

    @classmethod
    def is_user_blocked(cls, username):
        """Verifica se um usuário está bloqueado por muitas tentativas"""
        settings = GlobalSecuritySettings.get_settings()
        
        # Calcula o período de verificação
        from datetime import timedelta
        check_period = timezone.now() - timedelta(minutes=settings.lockout_duration_minutes)
        
        # Conta tentativas falhadas no período
        failed_attempts = cls.objects.filter(
            username=username,
            success=False,
            timestamp__gte=check_period
        ).count()
        
        return failed_attempts >= settings.max_login_attempts

    @classmethod
    def record_attempt(cls, username, ip_address, user_agent, success, failure_reason=None, app_name='', endpoint=''):
        """Registra uma tentativa de login"""
        return cls.objects.create(
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            failure_reason=failure_reason or '',
            app_name=app_name,
            endpoint=endpoint
        )


class UserActivitySummary(models.Model):
    """Resumo de atividade por usuário (tabela de agregação para performance)"""
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='activity_summary')
    
    # Contadores de atividade
    total_logins = models.PositiveIntegerField(default=0)
    total_searches = models.PositiveIntegerField(default=0)
    total_exports = models.PositiveIntegerField(default=0)
    total_admin_actions = models.PositiveIntegerField(default=0)
    
    # Atividade recente
    last_login = models.DateTimeField(null=True, blank=True)
    last_activity = models.DateTimeField(null=True, blank=True)
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    
    # Estatísticas de segurança
    failed_login_attempts_today = models.PositiveIntegerField(default=0)
    suspicious_activity_count = models.PositiveIntegerField(default=0)
    
    # Metadados
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Resumo de Atividade do Usuário"
        verbose_name_plural = "Resumos de Atividade dos Usuários"
    
    def __str__(self):
        return f"Atividade de {self.user.username}"

    def update_counters(self):
        """Atualiza os contadores baseado nos logs de auditoria"""
        # Buscar logs do usuário
        user_logs = GlobalAuditLog.objects.filter(user=self.user)
        
        # Atualizar contadores
        self.total_logins = user_logs.filter(action='login').count()
        self.total_searches = user_logs.filter(action='search').count()
        self.total_exports = user_logs.filter(action='report_export').count()
        self.total_admin_actions = user_logs.filter(
            action__in=['user_create', 'user_update', 'user_delete', 'config_change']
        ).count()
        
        # Última atividade
        last_log = user_logs.order_by('-timestamp').first()
        if last_log:
            self.last_activity = last_log.timestamp
            self.last_ip = last_log.ip_address
        
        # Último login
        last_login_log = user_logs.filter(action='login').order_by('-timestamp').first()
        if last_login_log:
            self.last_login = last_login_log.timestamp
        
        # Tentativas falhadas hoje
        today = timezone.now().date()
        self.failed_login_attempts_today = GlobalLoginAttempt.objects.filter(
            username=self.user.username,
            success=False,
            timestamp__date=today
        ).count()
        
        self.save()


# Signal para criar/atualizar resumo de atividade automaticamente
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=User)
def create_user_activity_summary(sender, instance, created, **kwargs):
    if created:
        UserActivitySummary.objects.create(user=instance)

@receiver(post_save, sender=GlobalAuditLog)
def update_user_activity_summary(sender, instance, created, **kwargs):
    if created:
        summary, created = UserActivitySummary.objects.get_or_create(user=instance.user)
        summary.update_counters()


class AuditEvent(models.Model):
    """Evento simplificado de auditoria para Auth e chamadas de API."""
    ACTION_CHOICES = [
        ('LOGIN_SUCCESS', 'Login Success'),
        ('LOGIN_FAIL', 'Login Fail'),
        ('LOGOUT', 'Logout'),
        ('REGISTER', 'Register'),
        ('TOKEN_REFRESH', 'Token Refresh'),
        ('API_CALL', 'API Call'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_events')
    action = models.CharField(max_length=32, choices=ACTION_CHOICES, db_index=True)
    ip = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    path = models.CharField(max_length=512)
    method = models.CharField(max_length=10)
    status_code = models.PositiveIntegerField()
    success = models.BooleanField(default=False)
    metadata = models.JSONField(default=dict, blank=True)
    correlation_id = models.CharField(max_length=64, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = 'Audit Event'
        verbose_name_plural = 'Audit Events'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['action', 'created_at']),
        ]

    def __str__(self):
        user_repr = self.user.username if self.user else 'anon'
        return f'{self.action} - {user_repr} - {self.created_at.strftime("%Y-%m-%d %H:%M:%S")}'