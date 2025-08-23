"""
URLs para o app networking - baseado nas rotas do l2vpn-master
Mantém compatibilidade com endpoints originais e adiciona novos endpoints REST
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Router para ViewSets
router = DefaultRouter()
router.register(r'cities', views.CityViewSet)
router.register(r'interfaces', views.NetworkInterfaceViewSet)
router.register(r'l2vpn', views.L2VPNConfigurationViewSet)
router.register(r'bgp', views.BGPConfigurationViewSet)
router.register(r'ospf', views.OSPFConfigurationViewSet)
router.register(r'logs', views.NetworkConfigurationLogViewSet)

urlpatterns = [
    # ViewSet URLs - LIMPO sem api redundante
    path('', include(router.urls)),
    
    # ==========================================
    # Endpoints compatíveis com l2vpn-master
    # ==========================================
    
    # L2VPN endpoints (rota original: /configure_l2vpn)
    path('configure_l2vpn/', views.configure_l2vpn, name='configure_l2vpn'),
    
    # BGP endpoints (rota original: /gerar_bgp)  
    path('gerar_bgp/', views.gerar_bgp, name='gerar_bgp'),
    
    # OSPF endpoints (rota original: /executar_config_ospf)
    path('executar_config_ospf/', views.executar_config_ospf, name='executar_config_ospf'),
    path('Config_OSPF/', views.config_ospf_page, name='config_ospf_page'),
    
    # Endpoints de compatibilidade (mantém /api/ por compatibilidade)
    path('cidades/', views.api_cities, name='api_cities'),
    
    # Endpoints de status e logs
    path('logs/<uuid:log_id>/status/', views.get_log_status, name='get_log_status'),
    path('status/commit/', views.get_commit_status, name='get_commit_status'),
    
    # Endpoint para teste de conectividade
    path('test-connection/', views.test_connection, name='test_connection'),
    
    # ==========================================
    # Endpoints REST modernos
    # ==========================================
    
    # Executar configurações específicas via ViewSets
    # Formato: /api/networking/{tipo}/{id}/execute/
    # Estes são automaticamente criados pelos ViewSets através dos @action decorators
    
    # Exemplos de uso:
    # POST /api/networking/l2vpn/{id}/execute/ - Executar configuração L2VPN
    # POST /api/networking/bgp/{id}/execute/ - Executar configuração BGP  
    # POST /api/networking/ospf/{id}/execute/ - Executar configuração OSPF
    
    # Listar e filtrar logs:
    # GET /api/networking/logs/?operation_type=l2vpn&status=success
    # GET /api/networking/logs/?target_ip=192.168.1.1
    
    # Filtrar interfaces por cidade:
    # GET /api/networking/interfaces/?city_id=123
]

# URLs com nomes mais descritivos para a API REST
app_name = 'networking'