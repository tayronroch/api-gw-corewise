from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    EquipmentViewSet, 
    LinkViewSet, 
    LinkTrafficHistoryViewSet, 
    link_traffic_percentile95,
    TopologyAPIView,
    NetworkMapView,
    TopologyProjectViewSet,
    TopologyNodeViewSet,
    TopologyConnectionViewSet,
    get_topology_projects,
    get_topology_project,
    save_topology_project,
    update_topology_project,
    delete_topology_project,
    save_topology_connections,
    save_topology_nodes,
)

# Import simplified views
from .views_simple import (
    test_simple_api,
    create_simple_topology_project,
    add_simple_network_device,
    create_simple_network_connection,
    get_simple_project_geojson,
    get_simple_project_summary,
    find_nearby_simple_devices,
    list_simple_projects,
    TopologyProjectSimpleViewSet,
    NetworkDeviceSimpleViewSet,
    NetworkConnectionSimpleViewSet,
)

router = DefaultRouter()
router.register(r'equipments', EquipmentViewSet)
router.register(r'links', LinkViewSet)
router.register(r'link-traffic-history', LinkTrafficHistoryViewSet)
router.register(r'projects', TopologyProjectViewSet)
router.register(r'nodes', TopologyNodeViewSet)
router.register(r'connections', TopologyConnectionViewSet)

# Simplified router - sem duplicação
simple_router = DefaultRouter()
simple_router.register(r'projects', TopologyProjectSimpleViewSet)
simple_router.register(r'devices', NetworkDeviceSimpleViewSet) 
simple_router.register(r'connections', NetworkConnectionSimpleViewSet)

urlpatterns = [
    # DRF Router URLs - Endpoints padrão REST
    path('', include(router.urls)),
    path('links/<int:link_id>/percentile95/', link_traffic_percentile95, name='link-traffic-percentile95'),
    
    # Topology Manager endpoints - PADRONIZADO SEM "api" redundante
    path('topology-projects/', get_topology_projects, name='get-topology-projects'),
    path('topology-projects/<str:project_id>/', get_topology_project, name='get-topology-project'),
    path('topology-projects/save/', save_topology_project, name='save-topology-project'),
    path('topology-projects/<str:project_id>/update/', update_topology_project, name='update-topology-project'),
    path('topology-projects/<str:project_id>/delete/', delete_topology_project, name='delete-topology-project'),
    path('topology-nodes/save/', save_topology_nodes, name='save-topology-nodes'),
    path('topology-connections/save/', save_topology_connections, name='save-topology-connections'),
    
    # Interactive topology endpoints - LIMPO
    path('interactive/topology/', TopologyAPIView.as_view({'get': 'list'}), name='topology-interactive'),
    path('interactive/network-map/', NetworkMapView.as_view({'get': 'list'}), name='network-map-interactive'),
    
    # Simplified API endpoints (sem GeoDjango) - PADRONIZADO
    path('simple/', include(simple_router.urls)),
    path('simple/test/', test_simple_api, name='simple-test-api'),
    path('simple/projects/create/', create_simple_topology_project, name='simple-create-project'),
    path('simple/projects/list/', list_simple_projects, name='simple-list-projects'),
    path('simple/projects/<uuid:project_id>/devices/add/', add_simple_network_device, name='simple-add-device'),
    path('simple/projects/<uuid:project_id>/connections/create/', create_simple_network_connection, name='simple-create-connection'),
    path('simple/projects/<uuid:project_id>/geojson/', get_simple_project_geojson, name='simple-project-geojson'),
    path('simple/projects/<uuid:project_id>/summary/', get_simple_project_summary, name='simple-project-summary'),
    path('simple/devices/nearby/', find_nearby_simple_devices, name='simple-nearby-devices'),
]
