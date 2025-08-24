from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings

# Imports condicionais baseados no banco de dados
try:
    if 'postgresql' in settings.DATABASES['default']['ENGINE']:
        from django.contrib.postgres.search import SearchVectorField, SearchVector
        from django.contrib.postgres.indexes import GinIndex
        POSTGRES_AVAILABLE = True
    else:
        POSTGRES_AVAILABLE = False
except:
    POSTGRES_AVAILABLE = False

# Fallback para SQLite
if not POSTGRES_AVAILABLE:
    class SearchVectorField(models.TextField):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
    
    class SearchVector:
        def __init__(self, *args, **kwargs):
            pass


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    require_mfa = models.BooleanField(default=True, help_text="Usuário deve usar MFA para fazer login")
    is_admin = models.BooleanField(default=False, help_text="Usuário tem acesso ao painel administrativo")
    last_password_change = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    mfa_secret = models.CharField(max_length=32, null=True, blank=True, help_text="Secret TOTP para MFA")
    mfa_enabled = models.BooleanField(default=False, help_text="MFA está ativo para este usuário")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Profile: {self.user.username}"
    
    def is_account_locked(self):
        if self.account_locked_until:
            return timezone.now() < self.account_locked_until
        return False
    
    def unlock_account(self):
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.save()


class Equipment(models.Model):
    name = models.CharField(max_length=100, unique=True)
    ip_address = models.GenericIPAddressField()
    location = models.CharField(max_length=100, blank=True)
    equipment_type = models.CharField(max_length=50, choices=[
        ('PE', 'Provider Edge'),
        ('CE', 'Customer Edge'),
        ('P', 'Provider')
    ])
    status = models.CharField(max_length=20, choices=[
        ('active', 'Ativo'),
        ('inactive', 'Inativo'),
        ('maintenance', 'Manutenção')
    ], default='active')
    last_backup = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name


class EquipmentJsonBackup(models.Model):
    """Armazena o JSON completo do equipamento Datacom DMOS"""
    equipment = models.ForeignKey(Equipment, on_delete=models.CASCADE, related_name='json_backups')
    backup_date = models.DateTimeField()
    json_data = models.JSONField(help_text="JSON completo do equipamento DMOS")
    file_name = models.CharField(max_length=255, blank=True)
    file_size = models.PositiveIntegerField(default=0)
    processed_at = models.DateTimeField(auto_now_add=True)
    
    # Campos extraídos para busca rápida
    total_interfaces = models.PositiveIntegerField(default=0)
    total_lags = models.PositiveIntegerField(default=0)  
    total_vpns = models.PositiveIntegerField(default=0)
    
    class Meta:
        ordering = ['-backup_date']
        unique_together = ['equipment', 'backup_date']
        indexes = [
            models.Index(fields=['equipment', '-backup_date']),
            models.Index(fields=['backup_date']),
        ]
    
    def __str__(self):
        return f"{self.equipment.name} JSON - {self.backup_date.strftime('%Y-%m-%d %H:%M')}"
    
    def extract_summary_data(self):
        """Extrai dados de resumo do JSON para busca rápida"""
        if not self.json_data:
            return
        
        data = self.json_data.get('data', {})
        
        # Contar LAGs
        link_agg = data.get('lacp:link-aggregation', {})
        lags = link_agg.get('interface', {}).get('lag', [])
        self.total_lags = len(lags) if lags else 0
        
        # Contar interfaces físicas
        interfaces_data = data.get('interfaces', {})  # Pode variar dependendo da estrutura
        self.total_interfaces = len(interfaces_data) if interfaces_data else 0
        
        # Contar VPNs (se existir na estrutura JSON)
        vpn_data = data.get('vpn', {})
        self.total_vpns = len(vpn_data) if vpn_data else 0
        
    def get_lags_data(self):
        """Retorna dados estruturados das LAGs"""
        if not self.json_data:
            return []
        
        data = self.json_data.get('data', {})
        link_agg = data.get('lacp:link-aggregation', {})
        lags = link_agg.get('interface', {}).get('lag', [])
        
        lag_data = []
        for lag in lags:
            lag_info = {
                'lag_id': lag.get('lag-id'),
                'description': lag.get('interface-lag-config', {}).get('description', ''),
                'mode': lag.get('interface-lag-config', {}).get('mode', ''),
                'load_balance': lag.get('interface-lag-config', {}).get('load-balance', ''),
                'members': [m.get('interface-name') for m in lag.get('interface-config', [])]
            }
            lag_data.append(lag_info)
        
        return lag_data
    
    def save(self, *args, **kwargs):
        # Extrair dados de resumo antes de salvar
        self.extract_summary_data()
        super().save(*args, **kwargs)


class MplsConfiguration(models.Model):
    equipment = models.ForeignKey(Equipment, on_delete=models.CASCADE, related_name='mpls_configs')
    backup_date = models.DateTimeField()
    raw_config = models.TextField()
    processed_at = models.DateTimeField(auto_now_add=True)
    search_vector = SearchVectorField(null=True, blank=True)
    
    # Relacionamento com o JSON completo
    json_backup = models.ForeignKey(
        EquipmentJsonBackup, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        help_text="Referência ao JSON completo de onde foram extraídos estes dados"
    )
    
    class Meta:
        ordering = ['-backup_date']
        indexes = [
            GinIndex(fields=['search_vector']) if POSTGRES_AVAILABLE else None,
        ] if POSTGRES_AVAILABLE else []
    
    def __str__(self):
        return f"{self.equipment.name} - {self.backup_date.strftime('%Y-%m-%d %H:%M')}"
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Atualiza o search vector após salvar
        self.update_search_vector()
    
    def update_search_vector(self):
        """Atualiza o vetor de busca com todo o conteúdo relevante"""
        if POSTGRES_AVAILABLE:
            MplsConfiguration.objects.filter(pk=self.pk).update(
                search_vector=SearchVector('equipment__name', weight='A') +
                             SearchVector('equipment__location', weight='B') +
                             SearchVector('raw_config', weight='C', config='portuguese_pt')
            )


class VpwsGroup(models.Model):
    mpls_config = models.ForeignKey(MplsConfiguration, on_delete=models.CASCADE, related_name='vpws_groups')
    group_name = models.CharField(max_length=100)
    
    def __str__(self):
        return f"{self.mpls_config.equipment.name} - {self.group_name}"


class Vpn(models.Model):
    ENCAPSULATION_TYPE_CHOICES = [
        ('untagged', 'Untagged'),
        ('vlan_tagged', 'VLAN Tagged'),
        ('qinq', 'QinQ'),
    ]
    
    vpws_group = models.ForeignKey(VpwsGroup, on_delete=models.CASCADE, related_name='vpns')
    vpn_id = models.IntegerField(db_index=True)  # Índice para busca rápida por ID
    description = models.CharField(max_length=200, blank=True, db_index=True)  # Descrição da VPN
    neighbor_ip = models.GenericIPAddressField()
    neighbor_hostname = models.CharField(max_length=100, blank=True)
    pw_type = models.CharField(max_length=50)
    pw_id = models.IntegerField()
    encapsulation = models.CharField(max_length=100, blank=True)
    encapsulation_type = models.CharField(max_length=20, choices=ENCAPSULATION_TYPE_CHOICES, default='untagged')
    access_interface = models.CharField(max_length=100, blank=True)
    
    class Meta:
        unique_together = ['vpws_group', 'vpn_id']
        indexes = [
            models.Index(fields=['vpn_id']),
            models.Index(fields=['description']),
        ]
    
    def __str__(self):
        return f"VPN {self.vpn_id} - {self.neighbor_ip}"


class LdpNeighbor(models.Model):
    mpls_config = models.ForeignKey(MplsConfiguration, on_delete=models.CASCADE, related_name='ldp_neighbors')
    neighbor_ip = models.GenericIPAddressField()
    targeted = models.BooleanField(default=False)
    
    class Meta:
        unique_together = ['mpls_config', 'neighbor_ip']
    
    def __str__(self):
        return f"{self.mpls_config.equipment.name} -> {self.neighbor_ip}"


class Interface(models.Model):
    INTERFACE_TYPE_CHOICES = [
        ('physical', 'Physical'),
        ('lag', 'LAG'),
    ]
    
    mpls_config = models.ForeignKey(MplsConfiguration, on_delete=models.CASCADE, related_name='interfaces')
    name = models.CharField(max_length=100)  # e.g., ten-gigabit-ethernet-1/1/1, lag-10
    description = models.CharField(max_length=200, blank=True)
    interface_type = models.CharField(max_length=20, choices=INTERFACE_TYPE_CHOICES)
    speed = models.CharField(max_length=20, blank=True)  # e.g., 10G, 100G
    is_customer_interface = models.BooleanField(default=False)
    
    class Meta:
        unique_together = ['mpls_config', 'name']
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['is_customer_interface']),
        ]
    
    def __str__(self):
        return f"{self.mpls_config.equipment.name} - {self.name}"


class LagMember(models.Model):
    lag_interface = models.ForeignKey(Interface, on_delete=models.CASCADE, related_name='members')
    member_interface_name = models.CharField(max_length=100)
    
    class Meta:
        unique_together = ['lag_interface', 'member_interface_name']
    
    def __str__(self):
        return f"{self.lag_interface.name} -> {self.member_interface_name}"


class CustomerService(models.Model):
    SERVICE_TYPE_CHOICES = [
        ('internet', 'Internet'),
        ('vpn', 'VPN'),
        ('voice', 'Voz'),
        ('data', 'Dados')
    ]
    
    name = models.CharField(max_length=100, db_index=True)
    vpn = models.ForeignKey(Vpn, on_delete=models.CASCADE, related_name='customer_services')
    service_type = models.CharField(max_length=50, choices=SERVICE_TYPE_CHOICES)
    bandwidth = models.CharField(max_length=50, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name


class BackupProcessLog(models.Model):
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=[
        ('running', 'Executando'),
        ('completed', 'Concluído'),
        ('failed', 'Falhou')
    ])
    processed_files = models.IntegerField(default=0)
    total_files = models.IntegerField(default=0)
    errors = models.TextField(blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    class Meta:
        ordering = ['-started_at']
    
    def __str__(self):
        return f"Backup Process - {self.started_at.strftime('%Y-%m-%d %H:%M')} - {self.status}"


class AccessLog(models.Model):
    STATUS_CHOICES = [
        ('success', 'Sucesso'),
        ('failed', 'Falha'),
        ('logout', 'Logout'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='access_logs')
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    session_key = models.CharField(max_length=40, blank=True)
    failure_reason = models.CharField(max_length=200, blank=True)
    
    class Meta:
        ordering = ['-login_time']
        indexes = [
            models.Index(fields=['user', '-login_time']),
            models.Index(fields=['ip_address', '-login_time']),
            models.Index(fields=['status', '-login_time']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.ip_address} - {self.login_time.strftime('%Y-%m-%d %H:%M:%S')}"


class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('search', 'Busca realizada'),
        ('report_export', 'Relatório exportado'),
        ('view_equipment', 'Visualizar equipamento'),
        ('view_vpn', 'Visualizar VPN'),
        ('backup_process', 'Processo de backup'),
        ('config_download', 'Download de configuração'),
        ('user_management', 'Gerenciamento de usuário'),
        ('system_settings', 'Configurações do sistema'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='audit_logs')
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    target_object_type = models.CharField(max_length=50, blank=True)  # e.g., 'Equipment', 'Vpn'
    target_object_id = models.PositiveIntegerField(null=True, blank=True)
    search_query = models.TextField(blank=True)  # Para buscas
    export_format = models.CharField(max_length=20, blank=True)  # Para exports (xlsx, csv, pdf)
    results_count = models.PositiveIntegerField(null=True, blank=True)  # Quantidade de resultados
    additional_data = models.JSONField(default=dict, blank=True)  # Dados extras em JSON
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
            models.Index(fields=['ip_address', '-timestamp']),
            models.Index(fields=['target_object_type', 'target_object_id']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.get_action_display()} - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"


class SecuritySettings(models.Model):
    """Configurações globais de segurança da aplicação"""
    
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
    
    # Configurações de auditoria
    audit_retention_days = models.PositiveIntegerField(
        default=90,
        help_text="Quantos dias manter logs de auditoria (0 = manter sempre)"
    )
    
    # Configurações de IP
    enable_ip_whitelist = models.BooleanField(
        default=False,
        help_text="Habilitar lista de IPs permitidos"
    )
    allowed_ips = models.TextField(
        blank=True,
        help_text="IPs permitidos (um por linha, suporta CIDR)"
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
        verbose_name = "Configurações de Segurança"
        verbose_name_plural = "Configurações de Segurança"
    
    def __str__(self):
        return f"Configurações de Segurança - Atualizado em {self.updated_at.strftime('%d/%m/%Y %H:%M')}"
    
    @classmethod
    def get_settings(cls):
        """Retorna as configurações atuais ou cria padrões se não existir"""
        settings, created = cls.objects.get_or_create(
            id=1,  # Sempre usar ID 1 para singleton
            defaults={
                'max_login_attempts': 5,
                'lockout_duration_minutes': 15,
                'session_timeout_minutes': 120,
                'audit_retention_days': 90,
                'password_min_length': 8,
                'password_require_uppercase': True,
                'password_require_lowercase': True,
                'password_require_numbers': True,
                'password_require_symbols': False,
            }
        )
        return settings


class LoginAttempt(models.Model):
    """Registro de tentativas de login para controle de segurança"""
    
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    success = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=200, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['username', 'ip_address', '-timestamp']),
            models.Index(fields=['ip_address', '-timestamp']),
            models.Index(fields=['success', '-timestamp']),
        ]
    
    def __str__(self):
        status = "Sucesso" if self.success else "Falha"
        return f"{self.username} - {status} - {self.timestamp.strftime('%d/%m/%Y %H:%M:%S')}"
    
    @classmethod
    def is_ip_blocked(cls, ip_address):
        """Verifica se um IP está bloqueado por muitas tentativas"""
        from django.utils import timezone
        from datetime import timedelta
        
        settings = SecuritySettings.get_settings()
        
        # Calcula o período de verificação
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
        from django.utils import timezone
        from datetime import timedelta
        
        settings = SecuritySettings.get_settings()
        
        # Calcula o período de verificação
        check_period = timezone.now() - timedelta(minutes=settings.lockout_duration_minutes)
        
        # Conta tentativas falhadas no período
        failed_attempts = cls.objects.filter(
            username=username,
            success=False,
            timestamp__gte=check_period
        ).count()
        
        return failed_attempts >= settings.max_login_attempts
    
    @classmethod
    def record_attempt(cls, username, ip_address, user_agent, success, failure_reason=None):
        """Registra uma tentativa de login"""
        return cls.objects.create(
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            failure_reason=failure_reason or ''
        )


# Signal para criar profile automaticamente
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'profile'):
        instance.profile.save()