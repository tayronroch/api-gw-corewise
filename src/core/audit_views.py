"""
Views para o sistema global de auditoria CoreWise
"""
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Count, Q
from django.contrib.auth.models import User
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters

from .audit_models import (
    GlobalAuditLog,
    GlobalAccessLog,
    GlobalSecuritySettings,
    GlobalLoginAttempt, 
    UserActivitySummary
)
from .audit_serializers import (
    GlobalAuditLogSerializer,
    GlobalAuditLogSummarySerializer,
    GlobalAccessLogSerializer,
    GlobalSecuritySettingsSerializer,
    GlobalLoginAttemptSerializer,
    UserActivitySummarySerializer,
    AuditStatsSerializer,
    SecurityDashboardSerializer,
    SearchAuditSerializer
)


class AuditPagination(PageNumberPagination):
    """Paginação customizada para logs de auditoria"""
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 200


class GlobalAuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet para logs de auditoria global - somente leitura"""
    
    queryset = GlobalAuditLog.objects.all().select_related('user', 'content_type')
    serializer_class = GlobalAuditLogSerializer
    pagination_class = AuditPagination
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    
    # Campos para filtros
    filterset_fields = {
        'user': ['exact'],
        'action': ['exact', 'in'],
        'app_name': ['exact', 'in'],
        'module_name': ['exact', 'in'],
        'success': ['exact'],
        'timestamp': ['gte', 'lte', 'range'],
        'ip_address': ['exact'],
    }
    
    # Campos para busca
    search_fields = [
        'user__username', 'description', 'search_query',
        'ip_address', 'endpoint', 'error_message'
    ]
    
    # Campos para ordenação
    ordering_fields = [
        'timestamp', 'user__username', 'action', 'app_name',
        'success', 'execution_time_ms'
    ]
    ordering = ['-timestamp']
    
    def get_serializer_class(self):
        """Usar serializer resumido para listagens"""
        if self.action == 'list':
            return GlobalAuditLogSummarySerializer
        return GlobalAuditLogSerializer
    
    def get_queryset(self):
        """Filtrar queryset baseado em permissões"""
        queryset = super().get_queryset()
        
        # Usuários não-staff só podem ver seus próprios logs
        if not self.request.user.is_staff:
            queryset = queryset.filter(user=self.request.user)
        
        return queryset
    
    @action(detail=False, methods=['get'])
    def my_activity(self, request):
        """Retornar logs de atividade do usuário atual"""
        logs = self.get_queryset().filter(user=request.user)[:20]
        serializer = GlobalAuditLogSummarySerializer(logs, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Estatísticas de auditoria - apenas para staff"""
        if not request.user.is_staff:
            return Response(
                {'error': 'Permissão negada'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Calcular estatísticas
        total_logs = GlobalAuditLog.objects.count()
        total_users = User.objects.count()
        
        # Estatísticas de login
        total_failed_logins = GlobalLoginAttempt.objects.filter(success=False).count()
        total_successful_logins = GlobalLoginAttempt.objects.filter(success=True).count()
        
        # Usuários mais ativos (últimos 7 dias)
        week_ago = timezone.now() - timedelta(days=7)
        most_active_users = (
            GlobalAuditLog.objects
            .filter(timestamp__gte=week_ago)
            .values('user__username')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        
        # Endpoints mais acessados
        most_accessed_endpoints = (
            GlobalAuditLog.objects
            .filter(timestamp__gte=week_ago)
            .values('endpoint')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        
        # Atividade por hora (últimas 24h)
        day_ago = timezone.now() - timedelta(days=1)
        activity_by_hour = []
        for i in range(24):
            hour_start = day_ago + timedelta(hours=i)
            hour_end = hour_start + timedelta(hours=1)
            count = GlobalAuditLog.objects.filter(
                timestamp__gte=hour_start,
                timestamp__lt=hour_end
            ).count()
            activity_by_hour.append({
                'hour': hour_start.strftime('%H:00'),
                'count': count
            })
        
        # Atividade por app
        activity_by_app = dict(
            GlobalAuditLog.objects
            .filter(timestamp__gte=week_ago)
            .values('app_name')
            .annotate(count=Count('id'))
            .values_list('app_name', 'count')
        )
        
        # Alertas de segurança (atividades suspeitas)
        security_alerts = GlobalAuditLog.objects.filter(
            action__in=['suspicious_activity', 'access_denied', 'rate_limit_exceeded'],
            timestamp__gte=week_ago
        ).count()
        
        # Estatísticas por período
        today = timezone.now().date()
        week_start = today - timedelta(days=7)
        month_start = today - timedelta(days=30)
        
        today_stats = {
            'total_logs': GlobalAuditLog.objects.filter(timestamp__date=today).count(),
            'unique_users': GlobalAuditLog.objects.filter(
                timestamp__date=today
            ).values('user').distinct().count(),
            'failed_logins': GlobalLoginAttempt.objects.filter(
                timestamp__date=today, success=False
            ).count(),
        }
        
        week_stats = {
            'total_logs': GlobalAuditLog.objects.filter(timestamp__date__gte=week_start).count(),
            'unique_users': GlobalAuditLog.objects.filter(
                timestamp__date__gte=week_start
            ).values('user').distinct().count(),
            'failed_logins': GlobalLoginAttempt.objects.filter(
                timestamp__date__gte=week_start, success=False
            ).count(),
        }
        
        month_stats = {
            'total_logs': GlobalAuditLog.objects.filter(timestamp__date__gte=month_start).count(),
            'unique_users': GlobalAuditLog.objects.filter(
                timestamp__date__gte=month_start
            ).values('user').distinct().count(),
            'failed_logins': GlobalLoginAttempt.objects.filter(
                timestamp__date__gte=month_start, success=False
            ).count(),
        }
        
        stats_data = {
            'total_logs': total_logs,
            'total_users': total_users,
            'total_failed_logins': total_failed_logins,
            'total_successful_logins': total_successful_logins,
            'most_active_users': list(most_active_users),
            'most_accessed_endpoints': list(most_accessed_endpoints),
            'activity_by_hour': activity_by_hour,
            'activity_by_app': activity_by_app,
            'security_alerts': security_alerts,
            'today_stats': today_stats,
            'week_stats': week_stats,
            'month_stats': month_stats,
        }
        
        serializer = AuditStatsSerializer(stats_data)
        return Response(serializer.data)


class GlobalAccessLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet para logs de acesso global - somente leitura"""
    
    queryset = GlobalAccessLog.objects.all().select_related('user')
    serializer_class = GlobalAccessLogSerializer
    pagination_class = AuditPagination
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    
    filterset_fields = {
        'user': ['exact'],
        'status': ['exact', 'in'],
        'app_name': ['exact', 'in'],
        'login_time': ['gte', 'lte', 'range'],
        'ip_address': ['exact'],
    }
    
    search_fields = ['user__username', 'ip_address', 'user_agent']
    ordering_fields = ['login_time', 'logout_time', 'user__username']
    ordering = ['-login_time']
    
    def get_queryset(self):
        """Filtrar queryset baseado em permissões"""
        queryset = super().get_queryset()
        
        # Usuários não-staff só podem ver seus próprios logs
        if not self.request.user.is_staff:
            queryset = queryset.filter(user=self.request.user)
        
        return queryset


class GlobalSecuritySettingsViewSet(viewsets.ModelViewSet):
    """ViewSet para configurações de segurança global"""
    
    queryset = GlobalSecuritySettings.objects.all()
    serializer_class = GlobalSecuritySettingsSerializer
    permission_classes = [permissions.IsAdminUser]
    
    def get_object(self):
        """Sempre retornar/criar as configurações singleton"""
        settings = GlobalSecuritySettings.get_settings()
        return settings
    
    def list(self, request):
        """Retornar as configurações atuais"""
        settings = self.get_object()
        serializer = self.get_serializer(settings)
        return Response(serializer.data)
    
    def update(self, request, pk=None):
        """Atualizar configurações"""
        settings = self.get_object()
        serializer = self.get_serializer(settings, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(updated_by=request.user)
            
            # Registrar alteração nas configurações
            GlobalAuditLog.log_action(
                user=request.user,
                action='config_change',
                description='Configurações de segurança alteradas',
                request=request,
                target_object=settings,
                new_values=serializer.validated_data
            )
            
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GlobalLoginAttemptViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet para tentativas de login global - somente leitura"""
    
    queryset = GlobalLoginAttempt.objects.all()
    serializer_class = GlobalLoginAttemptSerializer
    pagination_class = AuditPagination
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    
    filterset_fields = {
        'username': ['exact', 'icontains'],
        'success': ['exact'],
        'app_name': ['exact', 'in'],
        'timestamp': ['gte', 'lte', 'range'],
        'ip_address': ['exact'],
    }
    
    search_fields = ['username', 'ip_address', 'failure_reason']
    ordering_fields = ['timestamp', 'username', 'success']
    ordering = ['-timestamp']
    
    def get_queryset(self):
        """Filtrar queryset baseado em permissões"""
        queryset = super().get_queryset()
        
        # Usuários não-staff só podem ver suas próprias tentativas
        if not self.request.user.is_staff:
            queryset = queryset.filter(username=self.request.user.username)
        
        return queryset


class UserActivitySummaryViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet para resumos de atividade dos usuários"""
    
    queryset = UserActivitySummary.objects.all().select_related('user')
    serializer_class = UserActivitySummarySerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    
    filterset_fields = {
        'user': ['exact'],
        'failed_login_attempts_today': ['gte', 'lte'],
        'suspicious_activity_count': ['gte', 'lte'],
        'last_activity': ['gte', 'lte'],
    }
    
    search_fields = ['user__username', 'user__email', 'user__first_name', 'user__last_name']
    ordering_fields = [
        'user__username', 'total_logins', 'total_searches', 
        'last_activity', 'failed_login_attempts_today'
    ]
    ordering = ['-last_activity']
    
    def get_queryset(self):
        """Filtrar queryset baseado em permissões"""
        queryset = super().get_queryset()
        
        # Usuários não-staff só podem ver seu próprio resumo
        if not self.request.user.is_staff:
            queryset = queryset.filter(user=self.request.user)
        
        return queryset
    
    @action(detail=False, methods=['get'])
    def my_summary(self, request):
        """Retornar resumo de atividade do usuário atual"""
        try:
            summary = UserActivitySummary.objects.get(user=request.user)
            serializer = self.get_serializer(summary)
            return Response(serializer.data)
        except UserActivitySummary.DoesNotExist:
            return Response(
                {'error': 'Resumo de atividade não encontrado'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=True, methods=['post'])
    def update_counters(self, request, pk=None):
        """Atualizar contadores de atividade manualmente"""
        if not request.user.is_staff:
            return Response(
                {'error': 'Permissão negada'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        summary = self.get_object()
        summary.update_counters()
        
        return Response({
            'message': 'Contadores atualizados com sucesso',
            'summary': UserActivitySummarySerializer(summary).data
        })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def security_dashboard(request):
    """Dashboard de segurança com estatísticas importantes"""
    if not request.user.is_staff:
        return Response(
            {'error': 'Permissão negada'}, 
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Sessões ativas (aproximação baseada em logs de acesso recentes)
    hour_ago = timezone.now() - timedelta(hours=1)
    active_sessions = GlobalAccessLog.objects.filter(
        login_time__gte=hour_ago,
        logout_time__isnull=True
    ).count()
    
    # IPs bloqueados
    blocked_ips = set()
    for ip in GlobalLoginAttempt.objects.values_list('ip_address', flat=True).distinct():
        if GlobalLoginAttempt.is_ip_blocked(ip):
            blocked_ips.add(ip)
    
    # Usuários bloqueados
    blocked_users = set()
    for username in GlobalLoginAttempt.objects.values_list('username', flat=True).distinct():
        if GlobalLoginAttempt.is_user_blocked(username):
            blocked_users.add(username)
    
    # Tentativas falhadas hoje
    today = timezone.now().date()
    failed_logins_today = GlobalLoginAttempt.objects.filter(
        timestamp__date=today,
        success=False
    ).count()
    
    # Tentativas de login falhadas recentes
    recent_failed_attempts = GlobalLoginAttempt.objects.filter(
        success=False,
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).order_by('-timestamp')[:10]
    
    # Usuários com maior risco
    high_risk_users = UserActivitySummary.objects.filter(
        Q(suspicious_activity_count__gt=2) |
        Q(failed_login_attempts_today__gt=2)
    ).order_by('-suspicious_activity_count')[:10]
    
    # Atividades suspeitas recentes
    suspicious_activities = GlobalAuditLog.objects.filter(
        action__in=['suspicious_activity', 'access_denied', 'rate_limit_exceeded'],
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).order_by('-timestamp')[:10]
    
    # Configurações de segurança atuais
    security_settings = GlobalSecuritySettings.get_settings()
    
    # Alertas de segurança
    security_alerts = []
    
    if len(blocked_ips) > 5:
        security_alerts.append({
            'type': 'warning',
            'message': f'{len(blocked_ips)} IPs estão bloqueados por tentativas excessivas',
            'action': 'review_blocked_ips'
        })
    
    if len(blocked_users) > 0:
        security_alerts.append({
            'type': 'error',
            'message': f'{len(blocked_users)} usuários estão bloqueados',
            'action': 'review_blocked_users'
        })
    
    if failed_logins_today > 50:
        security_alerts.append({
            'type': 'warning',
            'message': f'{failed_logins_today} tentativas de login falharam hoje',
            'action': 'investigate_login_failures'
        })
    
    dashboard_data = {
        'active_sessions': active_sessions,
        'blocked_ips': len(blocked_ips),
        'blocked_users': len(blocked_users),
        'failed_logins_today': failed_logins_today,
        'recent_failed_attempts': GlobalLoginAttemptSerializer(
            recent_failed_attempts, many=True
        ).data,
        'high_risk_users': UserActivitySummarySerializer(
            high_risk_users, many=True
        ).data,
        'suspicious_activities': GlobalAuditLogSummarySerializer(
            suspicious_activities, many=True
        ).data,
        'security_settings': GlobalSecuritySettingsSerializer(
            security_settings
        ).data,
        'security_alerts': security_alerts,
    }
    
    serializer = SecurityDashboardSerializer(dashboard_data)
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([permissions.IsAdminUser])
def cleanup_old_logs(request):
    """Limpar logs antigos baseado nas configurações de retenção"""
    settings = GlobalSecuritySettings.get_settings()
    
    deleted_counts = {
        'audit_logs': 0,
        'access_logs': 0,
        'login_attempts': 0
    }
    
    # Limpar logs de auditoria
    if settings.audit_retention_days > 0:
        cutoff_date = timezone.now() - timedelta(days=settings.audit_retention_days)
        deleted_counts['audit_logs'] = GlobalAuditLog.objects.filter(
            timestamp__lt=cutoff_date
        ).delete()[0]
    
    # Limpar logs de acesso
    if settings.access_log_retention_days > 0:
        cutoff_date = timezone.now() - timedelta(days=settings.access_log_retention_days)
        deleted_counts['access_logs'] = GlobalAccessLog.objects.filter(
            login_time__lt=cutoff_date
        ).delete()[0]
        
        deleted_counts['login_attempts'] = GlobalLoginAttempt.objects.filter(
            timestamp__lt=cutoff_date
        ).delete()[0]
    
    # Registrar a limpeza
    GlobalAuditLog.log_action(
        user=request.user,
        action='system_maintenance',
        description='Limpeza automática de logs antigos executada',
        request=request,
        additional_data=deleted_counts
    )
    
    return Response({
        'message': 'Limpeza de logs concluída',
        'deleted_counts': deleted_counts
    })


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def health_check(request):
    """Endpoint de health check para monitoramento"""
    try:
        # Verificar se consegue conectar com o banco de dados
        GlobalSecuritySettings.get_settings()
        
        # Contar logs recentes para verificar se sistema está funcionando
        recent_logs = GlobalAuditLog.objects.filter(
            timestamp__gte=timezone.now() - timedelta(minutes=10)
        ).count()
        
        return Response({
            'status': 'healthy',
            'timestamp': timezone.now().isoformat(),
            'recent_activity': recent_logs > 0,
            'database': 'connected'
        })
    
    except Exception as e:
        return Response({
            'status': 'unhealthy',
            'timestamp': timezone.now().isoformat(),
            'error': str(e),
            'database': 'disconnected'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
