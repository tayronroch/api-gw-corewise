"""
Views para funcionalidades geoespaciais de topologia
TEMPORARIAMENTE DESABILITADO - Usando views simplificadas em views_simple.py
"""
# from rest_framework import viewsets, status
# from rest_framework.decorators import api_view, permission_classes, action
# from rest_framework.permissions import IsAuthenticated, AllowAny
# from rest_framework.response import Response
# from django.contrib.gis.geos import Point, LineString
# from django.contrib.gis.db.models.functions import Distance
# from django.http import JsonResponse
# from django.views.decorators.csrf import csrf_exempt
# from django.utils.decorators import method_decorator
# from .models_geo import TopologyProjectGeo, NetworkDeviceGeo, NetworkConnectionGeo
# from .services_geo import TopologyGeoExporter, PathCalculator, TopologyAnalyzer
# import json
# import uuid

# @api_view(['GET'])
# @permission_classes([AllowAny])
# def test_geo_api(request):
#     """Endpoint de teste para verificar conectividade"""
#     return Response({
#         'message': 'API Geoespacial funcionando!',
#         'status': 'OK'
#     })

# @api_view(['POST'])
# @permission_classes([AllowAny])  # Temporarily allow any for debugging
# def create_topology_project(request):
#     """Cria um novo projeto de topologia - TEMPORARILY DISABLED"""
#     return Response({
#         'error': 'GeoDjango models temporarily disabled - GDAL not installed'
#     }, status=status.HTTP_501_NOT_IMPLEMENTED)

# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def add_network_device(request, project_id):
#     """Adiciona dispositivo de rede ao projeto"""
#     try:
#         project = TopologyProjectGeo.objects.get(id=project_id)
#         data = request.data
        
#         device = NetworkDeviceGeo.objects.create(
#             project=project,
#             name=data['name'],
#             device_type=data['device_type'],
#             location=Point(data['longitude'], data['latitude'], srid=4326),
#             altitude=data.get('altitude'),
#             properties=data.get('properties', {}),
#             status=data.get('status', 'active')
#         )
        
#         # Recalcular bounds do projeto
#         project.calculate_bounds_from_devices()
        
#         return Response({
#             'success': True,
#             'device_id': str(device.id),
#             'message': 'Dispositivo adicionado com sucesso'
#         })
        
#     except TopologyProjectGeo.DoesNotExist:
#         return Response({
#             'error': 'Projeto não encontrado'
#         }, status=status.HTTP_404_NOT_FOUND)
#     except Exception as e:
#         return Response({
#             'error': f'Erro ao adicionar dispositivo: {str(e)}'
#         }, status=status.HTTP_400_BAD_REQUEST)

# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def create_network_connection(request, project_id):
#     """Cria conexão entre dispositivos"""
#     try:
#         project = TopologyProjectGeo.objects.get(id=project_id)
#         data = request.data
        
#         source_device = NetworkDeviceGeo.objects.get(id=data['source_device_id'])
#         target_device = NetworkDeviceGeo.objects.get(id=data['target_device_id'])
        
#         # Criar conexão
#         connection = NetworkConnectionGeo(
#             project=project,
#             source_device=source_device,
#             target_device=target_device,
#             connection_type=data['connection_type'],
#             properties=data.get('properties', {}),
#             style_properties=data.get('style_properties', {})
#         )
        
#         # Definir caminho
#         if data.get('path_coordinates'):
#             # Caminho customizado fornecido
#             connection.set_path_from_coordinates(data['path_coordinates'])
#             connection.calculation_method = 'manual'
#         elif data.get('calculate_path', False):
#             # Calcular caminho automaticamente
#             path_coords = PathCalculator.calculate_road_path(source_device, target_device)
#             connection.set_path_from_coordinates(path_coords)
#             connection.calculation_method = 'routing_api'
#             connection.is_calculated = True
#         else:
#             # Linha reta
#             connection.create_straight_line_path()
        
#         connection.save()
        
#         return Response({
#             'success': True,
#             'connection_id': str(connection.id),
#             'length_km': connection.length_kilometers,
#             'message': 'Conexão criada com sucesso'
#         })
        
#     except (TopologyProjectGeo.DoesNotExist, NetworkDeviceGeo.DoesNotExist):
#         return Response({
#             'error': 'Projeto ou dispositivo não encontrado'
#         }, status=status.HTTP_404_NOT_FOUND)
#     except Exception as e:
#         return Response({
#             'error': f'Erro ao criar conexão: {str(e)}'
#         }, status=status.HTTP_400_BAD_REQUEST)

# @api_view(['PUT'])
# @permission_classes([IsAuthenticated])
# def update_connection_path(request, connection_id):
#     """Atualiza caminho de uma conexão"""
#     try:
#         connection = NetworkConnectionGeo.objects.get(id=connection_id)
#         data = request.data
        
#         if 'path_coordinates' in data:
#             connection.set_path_from_coordinates(data['path_coordinates'])
#             connection.calculation_method = 'manual'
#             connection.is_calculated = False
#             connection.save()
            
#             return Response({
#                 'success': True,
#                 'length_km': connection.length_kilometers,
#                 'message': 'Caminho atualizado com sucesso'
#             })
        
#         return Response({
#             'error': 'Coordenadas do caminho não fornecidas'
#         }, status=status.HTTP_400_BAD_REQUEST)
        
#     except NetworkConnectionGeo.DoesNotExist:
#         return Response({
#             'error': 'Conexão não encontrada'
#         }, status=status.HTTP_404_NOT_FOUND)
#     except Exception as e:
#         return Response({
#             'error': f'Erro ao atualizar caminho: {str(e)}'
#         }, status=status.HTTP_400_BAD_REQUEST)

# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def get_project_geojson(request, project_id):
#     """Retorna projeto em formato GeoJSON"""
#     try:
#         project = TopologyProjectGeo.objects.get(id=project_id)
#         exporter = TopologyGeoExporter(project)
#         return exporter.export_to_geojson()
        
#     except TopologyProjectGeo.DoesNotExist:
#         return Response({
#             'error': 'Projeto não encontrado'
#         }, status=status.HTTP_404_NOT_FOUND)

# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def export_project_kml(request, project_id):
#     """Exporta projeto para KML"""
#     try:
#         project = TopologyProjectGeo.objects.get(id=project_id)
#         exporter = TopologyGeoExporter(project)
#         return exporter.export_to_kml()
        
#     except TopologyProjectGeo.DoesNotExist:
#         return Response({
#             'error': 'Projeto não encontrado'
#         }, status=status.HTTP_404_NOT_FOUND)

# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def export_project_kmz(request, project_id):
#     """Exporta projeto para KMZ"""
#     try:
#         project = TopologyProjectGeo.objects.get(id=project_id)
#         exporter = TopologyGeoExporter(project)
#         return exporter.export_to_kmz()
        
#     except TopologyProjectGeo.DoesNotExist:
#         return Response({
#             'error': 'Projeto não encontrado'
#         }, status=status.HTTP_404_NOT_FOUND)

# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def get_project_analytics(request, project_id):
#     """Retorna análises e métricas do projeto"""
#     try:
#         project = TopologyProjectGeo.objects.get(id=project_id)
#         analyzer = TopologyAnalyzer(project)
        
#         analytics = {
#             'project_info': {
#                 'id': str(project.id),
#                 'name': project.name,
#                 'created_at': project.created_at,
#                 'center': {
#                     'latitude': project.center_point.y,
#                     'longitude': project.center_point.x
#                 } if project.center_point else None
#             },
#             'metrics': analyzer.calculate_network_metrics(),
#             'isolated_devices': [
#                 {
#                     'id': str(device.id),
#                     'name': device.name,
#                     'type': device.device_type
#                 } for device in analyzer.find_isolated_devices()
#             ],
#             'network_density': analyzer.calculate_network_density()
#         }
        
#         return Response(analytics)
        
#     except TopologyProjectGeo.DoesNotExist:
#         return Response({
#             'error': 'Projeto não encontrado'
#         }, status=status.HTTP_404_NOT_FOUND)

# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def calculate_all_paths(request, project_id):
#     """Recalcula todos os caminhos do projeto usando roteamento automático"""
#     try:
#         project = TopologyProjectGeo.objects.get(id=project_id)
#         connections = project.connections.filter(calculation_method__in=['straight_line', 'manual'])
        
#         updated_count = 0
#         errors = []
        
#         for connection in connections:
#             try:
#                 path_coords = PathCalculator.calculate_road_path(
#                     connection.source_device, 
#                     connection.target_device
#                 )
#                 connection.set_path_from_coordinates(path_coords)
#                 connection.calculation_method = 'routing_api'
#                 connection.is_calculated = True
#                 connection.save()
#                 updated_count += 1
                
#             except Exception as e:
#                 errors.append(f"Erro na conexão {connection}: {str(e)}")
        
#         return Response({
#             'success': True,
#             'updated_connections': updated_count,
#             'total_connections': connections.count(),
#             'errors': errors,
#             'message': f'{updated_count} caminhos recalculados com sucesso'
#         })
        
#     except TopologyProjectGeo.DoesNotExist:
#         return Response({
#             'error': 'Projeto não encontrado'
#         }, status=status.HTTP_404_NOT_FOUND)

# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def find_nearby_devices(request):
#     """Encontra dispositivos próximos a uma coordenada"""
#     try:
#         latitude = float(request.GET.get('latitude'))
#         longitude = float(request.GET.get('longitude'))
#         radius_km = float(request.GET.get('radius_km', 10))
        
#         point = Point(longitude, latitude, srid=4326)
        
#         # Converter km para graus (aproximação)
#         radius_degrees = radius_km / 111.0
        
#         nearby_devices = NetworkDeviceGeo.objects.annotate(
#             distance=Distance('location', point)
#         ).filter(
#             location__distance_lte=(point, radius_degrees)
#         ).order_by('distance')[:20]
        
#         results = []
#         for device in nearby_devices:
#             results.append({
#                 'id': str(device.id),
#                 'name': device.name,
#                 'device_type': device.device_type,
#                 'project': device.project.name,
#                 'latitude': device.latitude,
#                 'longitude': device.longitude,
#                 'distance_km': round(device.distance.km, 2) if hasattr(device, 'distance') else None
#             })
        
#         return Response({
#             'nearby_devices': results,
#             'search_center': {'latitude': latitude, 'longitude': longitude},
#             'radius_km': radius_km
#         })
        
#     except (ValueError, TypeError):
#         return Response({
#             'error': 'Coordenadas inválidas'
#         }, status=status.HTTP_400_BAD_REQUEST)

# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def list_projects(request):
#     """Lista todos os projetos de topologia"""
#     projects = TopologyProjectGeo.objects.all().order_by('-created_at')
    
#     results = []
#     for project in projects:
#         analyzer = TopologyAnalyzer(project)
#         metrics = analyzer.calculate_network_metrics()
        
#         results.append({
#             'id': str(project.id),
#             'name': project.name,
#             'description': project.description,
#             'created_at': project.created_at,
#             'updated_at': project.updated_at,
#             'center': {
#                 'latitude': project.center_point.y,
#                 'longitude': project.center_point.x
#             } if project.center_point else None,
#             'zoom_level': project.zoom_level,
#             'device_count': metrics['total_devices'],
#             'connection_count': metrics['total_connections'],
#             'calculated_paths': metrics['calculated_paths'],
#             'total_length_km': metrics['total_length_km']
#         })
    
#     return Response({
#         'projects': results,
#         'total_count': len(results)
#     })