"""
Configuração do Django Admin para o sistema global de auditoria
"""
from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.db.models import Q
from .audit_models import (
    GlobalAuditLog,
    GlobalAccessLog, 
    GlobalSecuritySettings,
    GlobalLoginAttempt,
    UserActivitySummary
)


@admin.register(GlobalAuditLog)
class GlobalAuditLogAdmin(admin.ModelAdmin):
    list_display = [
        'timestamp', 'user', 'action_display', 'app_name', 
        'module_name', 'success_icon', 'ip_address'
    ]
    list_filter = [
        'action', 'app_name', 'module_name', 'success', 
        'timestamp', 'user'
    ]
    search_fields = [
        'user__username', 'description', 'search_query', 
        'ip_address', 'endpoint'
    ]
    readonly_fields = [
        'timestamp', 'user', 'action', 'description', 'ip_address',
        'user_agent', 'app_name', 'module_name', 'endpoint',
        'content_type', 'object_id', 'execution_time_ms', 'memory_usage_mb'
    ]
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']
    
    def action_display(self, obj):
        return obj.get_action_display()
    action_display.short_description = 'Ação'
    
    def success_icon(self, obj):
        if obj.success:
            return format_html('<span style="color: green;">✓</span>')
        else:
            return format_html('<span style="color: red;">✗</span>')
    success_icon.short_description = 'Status'
    
    def has_add_permission(self, request):
        return False  # Logs são criados automaticamente
    
    def has_change_permission(self, request, obj=None):
        return False  # Logs são imutáveis


@admin.register(GlobalAccessLog)
class GlobalAccessLogAdmin(admin.ModelAdmin):
    list_display = [
        'login_time', 'user', 'status', 'ip_address', 
        'app_name', 'session_duration'
    ]
    list_filter = [
        'status', 'app_name', 'login_time', 'user'
    ]
    search_fields = [
        'user__username', 'ip_address', 'user_agent', 'endpoint'
    ]
    readonly_fields = [
        'user', 'ip_address', 'user_agent', 'login_time', 
        'logout_time', 'status', 'session_key', 'failure_reason',
        'app_name', 'endpoint'
    ]
    date_hierarchy = 'login_time'
    ordering = ['-login_time']
    
    def session_duration(self, obj):
        if obj.logout_time and obj.login_time:
            duration = obj.logout_time - obj.login_time
            return f"{duration.total_seconds() // 60:.0f} min"
        return "Em andamento"
    session_duration.short_description = 'Duração'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(GlobalSecuritySettings)
class GlobalSecuritySettingsAdmin(admin.ModelAdmin):
    fieldsets = (
        ('Configurações de Login', {
            'fields': (
                'max_login_attempts', 'lockout_duration_minutes',
                'session_timeout_minutes', 'concurrent_sessions_limit'
            )
        }),
        ('Retenção de Logs', {
            'fields': (
                'audit_retention_days', 'access_log_retention_days'
            )
        }),
        ('Controle de IP', {
            'fields': (
                'enable_ip_whitelist', 'allowed_ips',
                'enable_geo_blocking', 'blocked_countries'
            )
        }),
        ('Políticas de Senha', {
            'fields': (
                'password_min_length', 'password_require_uppercase',
                'password_require_lowercase', 'password_require_numbers',
                'password_require_symbols', 'password_history_count'
            )
        }),
        ('Configurações MFA', {
            'fields': (
                'mfa_required_for_admin', 'mfa_required_for_all',
                'mfa_backup_codes_count'
            )
        }),
        ('Rate Limiting', {
            'fields': (
                'api_rate_limit_per_minute', 'search_rate_limit_per_minute',
                'export_rate_limit_per_hour'
            )
        }),
        ('Notificações', {
            'fields': (
                'notify_admin_on_failed_login', 'notify_admin_on_user_lockout',
                'notify_admin_on_suspicious_activity', 'admin_notification_email'
            )
        }),
        ('Metadados', {
            'fields': ('created_at', 'updated_at', 'updated_by'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ['created_at', 'updated_at']
    
    def has_add_permission(self, request):
        # Permitir apenas uma instância (singleton)
        return not GlobalSecuritySettings.objects.exists()
    
    def has_delete_permission(self, request, obj=None):
        return False  # Não permitir deletar configurações
    
    def save_model(self, request, obj, form, change):
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(GlobalLoginAttempt)
class GlobalLoginAttemptAdmin(admin.ModelAdmin):
    list_display = [
        'timestamp', 'username', 'success_icon', 'ip_address',
        'app_name', 'failure_reason'
    ]
    list_filter = [
        'success', 'app_name', 'timestamp'
    ]
    search_fields = [
        'username', 'ip_address', 'user_agent', 'failure_reason'
    ]
    readonly_fields = [
        'username', 'ip_address', 'user_agent', 'success',
        'failure_reason', 'timestamp', 'app_name', 'endpoint',
        'geolocation'
    ]
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']
    
    def success_icon(self, obj):
        if obj.success:
            return format_html('<span style="color: green;">✓ Sucesso</span>')
        else:
            return format_html('<span style="color: red;">✗ Falha</span>')
    success_icon.short_description = 'Status'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(UserActivitySummary)
class UserActivitySummaryAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'total_logins', 'total_searches', 'total_exports',
        'last_activity', 'failed_login_attempts_today', 'security_status'
    ]
    list_filter = [
        'last_activity', 'failed_login_attempts_today',
        'suspicious_activity_count'
    ]
    search_fields = ['user__username', 'user__email']
    readonly_fields = [
        'user', 'total_logins', 'total_searches', 'total_exports',
        'total_admin_actions', 'last_login', 'last_activity', 'last_ip',
        'failed_login_attempts_today', 'suspicious_activity_count',
        'created_at', 'updated_at'
    ]
    
    def security_status(self, obj):
        if obj.suspicious_activity_count > 5:
            return format_html('<span style="color: red;">⚠ Alto Risco</span>')
        elif obj.failed_login_attempts_today > 3:
            return format_html('<span style="color: orange;">⚠ Médio Risco</span>')
        else:
            return format_html('<span style="color: green;">✓ Normal</span>')
    security_status.short_description = 'Status de Segurança'
    
    actions = ['update_counters']
    
    def update_counters(self, request, queryset):
        for summary in queryset:
            summary.update_counters()
        self.message_user(request, f"Contadores atualizados para {queryset.count()} usuários.")
    update_counters.short_description = "Atualizar contadores de atividade"
    
    def has_add_permission(self, request):
        return False  # Criados automaticamente
    
    def has_delete_permission(self, request, obj=None):
        return False  # Manter histórico
