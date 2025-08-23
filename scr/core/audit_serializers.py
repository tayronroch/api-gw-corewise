"""
Serializers para o sistema global de auditoria CoreWise
"""
from rest_framework import serializers
from django.contrib.auth.models import User
from .audit_models import (
    GlobalAuditLog,
    GlobalAccessLog,
    GlobalSecuritySettings, 
    GlobalLoginAttempt,
    UserActivitySummary
)


class GlobalAuditLogSerializer(serializers.ModelSerializer):
    """Serializer para logs de auditoria global"""
    
    user_username = serializers.CharField(source='user.username', read_only=True)
    user_full_name = serializers.CharField(source='user.get_full_name', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    content_object_str = serializers.SerializerMethodField()
    execution_time_seconds = serializers.SerializerMethodField()
    
    class Meta:
        model = GlobalAuditLog
        fields = [
            'id', 'timestamp', 'user', 'user_username', 'user_full_name',
            'action', 'action_display', 'description', 'ip_address', 
            'user_agent', 'app_name', 'module_name', 'endpoint',
            'content_type', 'object_id', 'content_object_str',
            'search_query', 'export_format', 'results_count',
            'old_values', 'new_values', 'additional_data',
            'execution_time_ms', 'execution_time_seconds', 'memory_usage_mb',
            'success', 'error_message'
        ]
        read_only_fields = ['id', 'timestamp']
    
    def get_content_object_str(self, obj):
        """Representação string do objeto relacionado"""
        if obj.content_object:
            return str(obj.content_object)
        return None
    
    def get_execution_time_seconds(self, obj):
        """Converter tempo de execução para segundos"""
        if obj.execution_time_ms:
            return round(obj.execution_time_ms / 1000, 3)
        return None


class GlobalAuditLogSummarySerializer(serializers.ModelSerializer):
    """Serializer resumido para listagens de logs"""
    
    user_username = serializers.CharField(source='user.username', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    
    class Meta:
        model = GlobalAuditLog
        fields = [
            'id', 'timestamp', 'user_username', 'action_display', 
            'app_name', 'module_name', 'success', 'ip_address'
        ]


class GlobalAccessLogSerializer(serializers.ModelSerializer):
    """Serializer para logs de acesso global"""
    
    user_username = serializers.CharField(source='user.username', read_only=True)
    user_full_name = serializers.CharField(source='user.get_full_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    session_duration = serializers.SerializerMethodField()
    
    class Meta:
        model = GlobalAccessLog
        fields = [
            'id', 'user', 'user_username', 'user_full_name', 'ip_address',
            'user_agent', 'login_time', 'logout_time', 'status', 'status_display',
            'session_key', 'failure_reason', 'app_name', 'endpoint',
            'session_duration'
        ]
        read_only_fields = ['id', 'login_time']
    
    def get_session_duration(self, obj):
        """Calcular duração da sessão em minutos"""
        if obj.logout_time and obj.login_time:
            duration = obj.logout_time - obj.login_time
            return round(duration.total_seconds() / 60, 1)
        return None


class GlobalSecuritySettingsSerializer(serializers.ModelSerializer):
    """Serializer para configurações de segurança global"""
    
    updated_by_username = serializers.CharField(source='updated_by.username', read_only=True)
    
    class Meta:
        model = GlobalSecuritySettings
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate_max_login_attempts(self, value):
        """Validar número máximo de tentativas de login"""
        if value < 3:
            raise serializers.ValidationError(
                "O número mínimo de tentativas de login deve ser 3."
            )
        if value > 20:
            raise serializers.ValidationError(
                "O número máximo de tentativas de login não pode exceder 20."
            )
        return value
    
    def validate_lockout_duration_minutes(self, value):
        """Validar duração do bloqueio"""
        if value < 5:
            raise serializers.ValidationError(
                "A duração mínima do bloqueio deve ser 5 minutos."
            )
        if value > 1440:  # 24 horas
            raise serializers.ValidationError(
                "A duração máxima do bloqueio não pode exceder 24 horas (1440 minutos)."
            )
        return value
    
    def validate_password_min_length(self, value):
        """Validar comprimento mínimo da senha"""
        if value < 6:
            raise serializers.ValidationError(
                "O comprimento mínimo da senha deve ser pelo menos 6 caracteres."
            )
        if value > 128:
            raise serializers.ValidationError(
                "O comprimento máximo da senha não pode exceder 128 caracteres."
            )
        return value


class GlobalLoginAttemptSerializer(serializers.ModelSerializer):
    """Serializer para tentativas de login global"""
    
    success_display = serializers.SerializerMethodField()
    time_ago = serializers.SerializerMethodField()
    
    class Meta:
        model = GlobalLoginAttempt
        fields = [
            'id', 'username', 'ip_address', 'user_agent', 'success',
            'success_display', 'failure_reason', 'timestamp', 'time_ago',
            'app_name', 'endpoint', 'geolocation'
        ]
        read_only_fields = ['id', 'timestamp']
    
    def get_success_display(self, obj):
        """Exibição amigável do status"""
        return "Sucesso" if obj.success else "Falha"
    
    def get_time_ago(self, obj):
        """Tempo transcorrido desde a tentativa"""
        from django.utils.timesince import timesince
        return timesince(obj.timestamp)


class UserActivitySummarySerializer(serializers.ModelSerializer):
    """Serializer para resumo de atividade do usuário"""
    
    username = serializers.CharField(source='user.username', read_only=True)
    user_full_name = serializers.CharField(source='user.get_full_name', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    is_active = serializers.BooleanField(source='user.is_active', read_only=True)
    is_staff = serializers.BooleanField(source='user.is_staff', read_only=True)
    security_risk_level = serializers.SerializerMethodField()
    last_activity_ago = serializers.SerializerMethodField()
    
    class Meta:
        model = UserActivitySummary
        fields = [
            'id', 'user', 'username', 'user_full_name', 'user_email',
            'is_active', 'is_staff', 'total_logins', 'total_searches',
            'total_exports', 'total_admin_actions', 'last_login',
            'last_activity', 'last_activity_ago', 'last_ip',
            'failed_login_attempts_today', 'suspicious_activity_count',
            'security_risk_level', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_security_risk_level(self, obj):
        """Calcular nível de risco de segurança"""
        if obj.suspicious_activity_count > 5:
            return {'level': 'high', 'label': 'Alto Risco', 'color': 'red'}
        elif obj.failed_login_attempts_today > 3 or obj.suspicious_activity_count > 2:
            return {'level': 'medium', 'label': 'Médio Risco', 'color': 'orange'}
        else:
            return {'level': 'low', 'label': 'Baixo Risco', 'color': 'green'}
    
    def get_last_activity_ago(self, obj):
        """Tempo desde a última atividade"""
        if obj.last_activity:
            from django.utils.timesince import timesince
            return timesince(obj.last_activity)
        return None


class AuditStatsSerializer(serializers.Serializer):
    """Serializer para estatísticas de auditoria"""
    
    total_logs = serializers.IntegerField()
    total_users = serializers.IntegerField()
    total_failed_logins = serializers.IntegerField()
    total_successful_logins = serializers.IntegerField()
    most_active_users = serializers.ListField()
    most_accessed_endpoints = serializers.ListField()
    activity_by_hour = serializers.ListField()
    activity_by_app = serializers.DictField()
    security_alerts = serializers.IntegerField()
    
    # Estatísticas por período
    today_stats = serializers.DictField()
    week_stats = serializers.DictField()
    month_stats = serializers.DictField()


class SecurityDashboardSerializer(serializers.Serializer):
    """Serializer para dashboard de segurança"""
    
    # Estatísticas gerais
    active_sessions = serializers.IntegerField()
    blocked_ips = serializers.IntegerField()
    blocked_users = serializers.IntegerField()
    failed_logins_today = serializers.IntegerField()
    
    # Tentativas de login recentes
    recent_failed_attempts = GlobalLoginAttemptSerializer(many=True)
    
    # Usuários com maior risco
    high_risk_users = UserActivitySummarySerializer(many=True)
    
    # Atividades suspeitas
    suspicious_activities = GlobalAuditLogSummarySerializer(many=True)
    
    # Configurações de segurança atuais
    security_settings = GlobalSecuritySettingsSerializer()
    
    # Alertas de segurança
    security_alerts = serializers.ListField()


class SearchAuditSerializer(serializers.Serializer):
    """Serializer para busca em logs de auditoria"""
    
    # Filtros de busca
    user = serializers.CharField(required=False)
    action = serializers.CharField(required=False)
    app_name = serializers.CharField(required=False)
    module_name = serializers.CharField(required=False)
    ip_address = serializers.CharField(required=False)
    date_from = serializers.DateTimeField(required=False)
    date_to = serializers.DateTimeField(required=False)
    success = serializers.BooleanField(required=False)
    
    # Parâmetros de paginação
    page = serializers.IntegerField(default=1, min_value=1)
    page_size = serializers.IntegerField(default=20, min_value=1, max_value=100)
    
    # Ordenação
    order_by = serializers.CharField(default='-timestamp')
    
    def validate(self, data):
        """Validar parâmetros de busca"""
        date_from = data.get('date_from')
        date_to = data.get('date_to')
        
        if date_from and date_to and date_from > date_to:
            raise serializers.ValidationError(
                "A data inicial deve ser anterior à data final."
            )
        
        return data