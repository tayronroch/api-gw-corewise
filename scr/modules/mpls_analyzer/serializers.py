"""
Django REST Framework serializers para o MPLS Analyzer
Sistema integrado ao CoreWise para análise de configurações MPLS
"""
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    Equipment, MplsConfiguration, VpwsGroup, Vpn, LdpNeighbor, 
    Interface, LagMember, CustomerService, BackupProcessLog,
    AccessLog, AuditLog, SecuritySettings, LoginAttempt, UserProfile
)


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer para perfis de usuários MPLS"""
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = UserProfile
        fields = [
            'id', 'username', 'email', 'full_name', 'require_mfa', 
            'is_admin', 'mfa_enabled', 'last_password_change',
            'failed_login_attempts', 'account_locked_until',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'username', 'email', 'failed_login_attempts', 
            'account_locked_until', 'created_at', 'updated_at'
        ]
    
    def get_full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip()


class EquipmentSerializer(serializers.ModelSerializer):
    """Serializer para equipamentos MPLS"""
    total_configs = serializers.SerializerMethodField()
    last_backup_formatted = serializers.SerializerMethodField()
    
    class Meta:
        model = Equipment
        fields = [
            'id', 'name', 'ip_address', 'location', 'equipment_type',
            'status', 'last_backup', 'last_backup_formatted',
            'total_configs', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_total_configs(self, obj):
        return obj.mpls_configs.count()
    
    def get_last_backup_formatted(self, obj):
        if obj.last_backup:
            return obj.last_backup.strftime('%d/%m/%Y %H:%M')
        return None
    
    def validate_ip_address(self, value):
        """Validar formato do IP"""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            raise serializers.ValidationError("Formato de IP inválido")


class MplsConfigurationSerializer(serializers.ModelSerializer):
    """Serializer para configurações MPLS"""
    equipment_name = serializers.CharField(source='equipment.name', read_only=True)
    equipment_type = serializers.CharField(source='equipment.equipment_type', read_only=True)
    equipment_location = serializers.CharField(source='equipment.location', read_only=True)
    backup_date_formatted = serializers.SerializerMethodField()
    config_size = serializers.SerializerMethodField()
    
    class Meta:
        model = MplsConfiguration
        fields = [
            'id', 'equipment', 'equipment_name', 'equipment_type', 
            'equipment_location', 'backup_date', 'backup_date_formatted',
            'raw_config', 'config_size', 'processed_at'
        ]
        read_only_fields = ['id', 'processed_at']
    
    def get_backup_date_formatted(self, obj):
        return obj.backup_date.strftime('%d/%m/%Y %H:%M:%S')
    
    def get_config_size(self, obj):
        return len(obj.raw_config)


class VpwsGroupSerializer(serializers.ModelSerializer):
    """Serializer para grupos VPWS"""
    equipment_name = serializers.CharField(source='mpls_config.equipment.name', read_only=True)
    vpns_count = serializers.SerializerMethodField()
    
    class Meta:
        model = VpwsGroup
        fields = [
            'id', 'mpls_config', 'equipment_name', 'group_name', 'vpns_count'
        ]
        read_only_fields = ['id']
    
    def get_vpns_count(self, obj):
        return obj.vpns.count()


class VpnSerializer(serializers.ModelSerializer):
    """Serializer para VPNs MPLS"""
    equipment_name = serializers.CharField(source='vpws_group.mpls_config.equipment.name', read_only=True)
    vpws_group_name = serializers.CharField(source='vpws_group.group_name', read_only=True)
    services_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Vpn
        fields = [
            'id', 'vpws_group', 'vpws_group_name', 'equipment_name',
            'vpn_id', 'description', 'neighbor_ip', 'neighbor_hostname',
            'pw_type', 'pw_id', 'encapsulation', 'encapsulation_type',
            'access_interface', 'services_count'
        ]
        read_only_fields = ['id']
    
    def get_services_count(self, obj):
        return obj.customer_services.count()
    
    def validate_neighbor_ip(self, value):
        """Validar formato do IP do vizinho"""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            raise serializers.ValidationError("Formato de IP inválido")


class LdpNeighborSerializer(serializers.ModelSerializer):
    """Serializer para vizinhos LDP"""
    equipment_name = serializers.CharField(source='mpls_config.equipment.name', read_only=True)
    
    class Meta:
        model = LdpNeighbor
        fields = [
            'id', 'mpls_config', 'equipment_name', 'neighbor_ip', 'targeted'
        ]
        read_only_fields = ['id']
    
    def validate_neighbor_ip(self, value):
        """Validar formato do IP do vizinho LDP"""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            raise serializers.ValidationError("Formato de IP inválido")


class LagMemberSerializer(serializers.ModelSerializer):
    """Serializer para membros de LAG"""
    
    class Meta:
        model = LagMember
        fields = ['id', 'lag_interface', 'member_interface_name']
        read_only_fields = ['id']


class InterfaceSerializer(serializers.ModelSerializer):
    """Serializer para interfaces MPLS"""
    equipment_name = serializers.CharField(source='mpls_config.equipment.name', read_only=True)
    members = LagMemberSerializer(many=True, read_only=True)
    members_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Interface
        fields = [
            'id', 'mpls_config', 'equipment_name', 'name', 'description',
            'interface_type', 'speed', 'is_customer_interface',
            'members', 'members_count'
        ]
        read_only_fields = ['id']
    
    def get_members_count(self, obj):
        return obj.members.count() if obj.interface_type == 'lag' else 0


class CustomerServiceSerializer(serializers.ModelSerializer):
    """Serializer para serviços de clientes"""
    vpn_id = serializers.CharField(source='vpn.vpn_id', read_only=True)
    vpn_description = serializers.CharField(source='vpn.description', read_only=True)
    equipment_name = serializers.CharField(source='vpn.vpws_group.mpls_config.equipment.name', read_only=True)
    
    class Meta:
        model = CustomerService
        fields = [
            'id', 'name', 'vpn', 'vpn_id', 'vpn_description', 
            'equipment_name', 'service_type', 'bandwidth', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class BackupProcessLogSerializer(serializers.ModelSerializer):
    """Serializer para logs de processamento de backup"""
    username = serializers.CharField(source='user.username', read_only=True)
    duration = serializers.SerializerMethodField()
    started_at_formatted = serializers.SerializerMethodField()
    finished_at_formatted = serializers.SerializerMethodField()
    
    class Meta:
        model = BackupProcessLog
        fields = [
            'id', 'started_at', 'started_at_formatted', 'finished_at', 
            'finished_at_formatted', 'status', 'processed_files',
            'total_files', 'errors', 'user', 'username', 'duration'
        ]
        read_only_fields = ['id']
    
    def get_duration(self, obj):
        if obj.finished_at and obj.started_at:
            delta = obj.finished_at - obj.started_at
            return str(delta)
        return None
    
    def get_started_at_formatted(self, obj):
        return obj.started_at.strftime('%d/%m/%Y %H:%M:%S')
    
    def get_finished_at_formatted(self, obj):
        if obj.finished_at:
            return obj.finished_at.strftime('%d/%m/%Y %H:%M:%S')
        return None


class AccessLogSerializer(serializers.ModelSerializer):
    """Serializer para logs de acesso"""
    username = serializers.CharField(source='user.username', read_only=True)
    login_time_formatted = serializers.SerializerMethodField()
    logout_time_formatted = serializers.SerializerMethodField()
    session_duration = serializers.SerializerMethodField()
    
    class Meta:
        model = AccessLog
        fields = [
            'id', 'user', 'username', 'ip_address', 'user_agent',
            'login_time', 'login_time_formatted', 'logout_time',
            'logout_time_formatted', 'status', 'session_key',
            'failure_reason', 'session_duration'
        ]
        read_only_fields = ['id']
    
    def get_login_time_formatted(self, obj):
        return obj.login_time.strftime('%d/%m/%Y %H:%M:%S')
    
    def get_logout_time_formatted(self, obj):
        if obj.logout_time:
            return obj.logout_time.strftime('%d/%m/%Y %H:%M:%S')
        return None
    
    def get_session_duration(self, obj):
        if obj.logout_time and obj.login_time:
            delta = obj.logout_time - obj.login_time
            return str(delta)
        return None


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer para logs de auditoria"""
    username = serializers.CharField(source='user.username', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    timestamp_formatted = serializers.SerializerMethodField()
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'user', 'username', 'action', 'action_display',
            'description', 'ip_address', 'user_agent', 'timestamp',
            'timestamp_formatted', 'target_object_type', 'target_object_id',
            'search_query', 'export_format', 'results_count', 'additional_data'
        ]
        read_only_fields = ['id']
    
    def get_timestamp_formatted(self, obj):
        return obj.timestamp.strftime('%d/%m/%Y %H:%M:%S')


class SecuritySettingsSerializer(serializers.ModelSerializer):
    """Serializer para configurações de segurança"""
    updated_by_username = serializers.CharField(source='updated_by.username', read_only=True)
    
    class Meta:
        model = SecuritySettings
        fields = [
            'id', 'max_login_attempts', 'lockout_duration_minutes',
            'session_timeout_minutes', 'audit_retention_days',
            'enable_ip_whitelist', 'allowed_ips', 'password_min_length',
            'password_require_uppercase', 'password_require_lowercase',
            'password_require_numbers', 'password_require_symbols',
            'created_at', 'updated_at', 'updated_by', 'updated_by_username'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class LoginAttemptSerializer(serializers.ModelSerializer):
    """Serializer para tentativas de login"""
    timestamp_formatted = serializers.SerializerMethodField()
    success_display = serializers.SerializerMethodField()
    
    class Meta:
        model = LoginAttempt
        fields = [
            'id', 'username', 'ip_address', 'user_agent', 'success',
            'success_display', 'failure_reason', 'timestamp', 'timestamp_formatted'
        ]
        read_only_fields = ['id']
    
    def get_timestamp_formatted(self, obj):
        return obj.timestamp.strftime('%d/%m/%Y %H:%M:%S')
    
    def get_success_display(self, obj):
        return "Sucesso" if obj.success else "Falha"


# ==========================================
# Serializers para relatórios e buscas
# ==========================================

class SearchResultSerializer(serializers.Serializer):
    """Serializer para resultados de busca no sistema MPLS"""
    equipment_name = serializers.CharField()
    equipment_type = serializers.CharField()
    equipment_location = serializers.CharField()
    vpn_id = serializers.IntegerField(required=False, allow_null=True)
    vpn_description = serializers.CharField(required=False, allow_blank=True)
    customer_name = serializers.CharField(required=False, allow_blank=True)
    service_type = serializers.CharField(required=False, allow_blank=True)
    match_type = serializers.CharField()  # 'equipment', 'vpn', 'customer', 'config'
    match_text = serializers.CharField()  # Texto que fez match
    confidence = serializers.FloatField(required=False)


class CustomerReportSerializer(serializers.Serializer):
    """Serializer para relatórios de clientes"""
    customer_name = serializers.CharField()
    service_count = serializers.IntegerField()
    service_types = serializers.ListField(child=serializers.CharField())
    equipments = serializers.ListField(child=serializers.CharField())
    vpns = serializers.ListField(child=serializers.DictField())
    total_bandwidth = serializers.CharField(required=False)
    last_seen = serializers.DateTimeField(required=False)


class EquipmentSummarySerializer(serializers.Serializer):
    """Serializer para resumo de equipamentos"""
    name = serializers.CharField()
    type = serializers.CharField()
    location = serializers.CharField()
    vpns_count = serializers.IntegerField()
    customers_count = serializers.IntegerField()
    interfaces_count = serializers.IntegerField()
    last_backup = serializers.DateTimeField()
    status = serializers.CharField()


class NetworkTopologySerializer(serializers.Serializer):
    """Serializer para dados de topologia de rede"""
    nodes = serializers.ListField(child=serializers.DictField())
    links = serializers.ListField(child=serializers.DictField())
    statistics = serializers.DictField()


# ==========================================
# Serializers para ações administrativas
# ==========================================

class BulkUpdateEquipmentSerializer(serializers.Serializer):
    """Serializer para atualização em lote de equipamentos"""
    equipment_ids = serializers.ListField(child=serializers.IntegerField())
    status = serializers.ChoiceField(choices=Equipment.STATUS_CHOICES, required=False)
    location = serializers.CharField(max_length=100, required=False)


class ProcessBackupSerializer(serializers.Serializer):
    """Serializer para processamento de backups"""
    backup_directory = serializers.CharField(max_length=500)
    force_reprocess = serializers.BooleanField(default=False)
    delete_existing = serializers.BooleanField(default=False)


class SearchQuerySerializer(serializers.Serializer):
    """Serializer para queries de busca"""
    query = serializers.CharField(max_length=1000)
    search_type = serializers.ChoiceField(
        choices=[
            ('auto', 'Detecção Automática'),
            ('equipment', 'Equipamento'),
            ('customer', 'Cliente'),
            ('vpn_id', 'ID da VPN'),
            ('ip', 'Endereço IP'),
            ('text', 'Texto Livre')
        ],
        default='auto'
    )
    limit = serializers.IntegerField(default=50, min_value=1, max_value=1000)
    include_config = serializers.BooleanField(default=False)