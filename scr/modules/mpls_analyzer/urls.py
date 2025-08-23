"""
URLs para o app MPLS Analyzer integrado ao CoreWise
Sistema completo de análise MPLS com funcionalidades preservadas
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Router para ViewSets principais
router = DefaultRouter()
router.register(r'equipments', views.EquipmentViewSet)
router.register(r'configurations', views.MplsConfigurationViewSet)
router.register(r'vpws-groups', views.VpwsGroupViewSet)
router.register(r'vpns', views.VpnViewSet)
router.register(r'ldp-neighbors', views.LdpNeighborViewSet)
router.register(r'interfaces', views.InterfaceViewSet)
router.register(r'customer-services', views.CustomerServiceViewSet)
router.register(r'backup-logs', views.BackupProcessLogViewSet)
router.register(r'access-logs', views.AccessLogViewSet)
router.register(r'audit-logs', views.AuditLogViewSet)
router.register(r'login-attempts', views.LoginAttemptViewSet)
router.register(r'user-profiles', views.UserProfileViewSet)

urlpatterns = [
    # ViewSets REST padrão
    path('', include(router.urls)),
    
    # ==========================================
    # Endpoints de busca inteligente
    # ==========================================
    path('search/', views.intelligent_search, name='intelligent-search'),
    path('search/advanced/', views.advanced_search, name='advanced-search'),
    path('search/suggestions/', views.search_suggestions, name='search-suggestions'),
    
    # ==========================================
    # Endpoints de relatórios
    # ==========================================
    path('reports/customers/', views.customer_report, name='customer-report'),
    path('reports/equipment-summary/', views.equipment_summary, name='equipment-summary'),
    path('reports/network-topology/', views.network_topology, name='network-topology'),
    path('reports/vpn/', views.vpn_report, name='vpn-report'),
    path('reports/customer-interfaces/', views.customer_interface_report, name='customer-interface-report'),
    path('reports/customers/excel/', views.customer_report_excel, name='customer-report-excel'),
    path('reports/export/', views.export_report, name='export-report'),
    
    # ==========================================
    # Endpoints de administração
    # ==========================================
    path('admin/process-backups/', views.process_backups, name='process-backups'),
    path('admin/bulk-update-equipment/', views.bulk_update_equipment, name='bulk-update-equipment'),
    path('admin/security-settings/', views.security_settings, name='security-settings'),
    path('admin/system-stats/', views.system_statistics, name='system-stats'),
    
    # ==========================================
    # Endpoints de dashboard
    # ==========================================
    path('dashboard/overview/', views.dashboard_overview, name='dashboard-overview'),
    path('dashboard/recent-activity/', views.recent_activity, name='recent-activity'),
    path('dashboard/alerts/', views.system_alerts, name='system-alerts'),
    
    # ==========================================
    # Endpoints de compatibilidade com sistema original
    # ==========================================
    path('legacy/search/', views.legacy_search, name='legacy-search'),
    path('legacy/customer-report/<str:customer_name>/', views.legacy_customer_report, name='legacy-customer-report'),
    
    # ==========================================
    # Endpoints de configuração e manutenção
    # ==========================================
    path('maintenance/update-search-vectors/', views.update_search_vectors, name='update-search-vectors'),
    path('maintenance/cleanup-logs/', views.cleanup_old_logs, name='cleanup-logs'),
    path('maintenance/backup-database/', views.backup_database, name='backup-database'),
    
    # ==========================================
    # Endpoints de gerenciamento de rede integrado
    # ==========================================
    path('network/scan/', views.network_scan_api, name='network-scan-api'),
    path('backup/execute/', views.backup_execute_api, name='backup-execute-api'),
    path('backup/status/', views.backup_status_api, name='backup-status-api'),
    path('fix-json/', views.fix_json_api, name='fix-json-api'),
    
    # ==========================================
    # Endpoints de monitoramento
    # ==========================================
    path('health/', views.health_check, name='health-check'),
    path('metrics/', views.system_metrics, name='system-metrics'),
]

# URLs com namespace
app_name = 'mpls_analyzer'
