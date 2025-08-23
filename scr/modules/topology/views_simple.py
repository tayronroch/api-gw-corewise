"""
Views simplificadas para funcionalidades de topologia sem GeoDjango
"""
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from .models_simple import (
    TopologyProjectSimple, 
    NetworkDeviceSimple, 
    NetworkConnectionSimple,
    TopologySnapshotSimple
)
import json
import uuid
import math

@api_view(['GET'])
@permission_classes([AllowAny])
def test_simple_api(request):
    """Endpoint de teste para verificar conectividade"""
    return Response({
        'message': 'API Simplificada funcionando!',
        'status': 'OK'
    })

@api_view(['POST'])
@permission_classes([AllowAny])  # Temporariamente AllowAny para testes
def create_simple_topology_project(request):
    """Cria um novo projeto de topologia simplificado"""
    try:
        data = request.data
        
        project = TopologyProjectSimple.objects.create(
            name=data['name'],
            description=data.get('description', ''),
            center_latitude=data.get('center_latitude', -23.5505),  # São Paulo como padrão
            center_longitude=data.get('center_longitude', -46.6333),
            zoom_level=data.get('zoom_level', 10)
        )
        
        return Response({
            'success': True,
            'project_id': str(project.id),
            'message': 'Projeto criado com sucesso'
        })
        
    except Exception as e:
        return Response({
            'error': f'Erro ao criar projeto: {str(e)}'
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])  # Temporariamente AllowAny para testes
def add_simple_network_device(request, project_id):
    """Adiciona dispositivo de rede ao projeto"""
    try:
        project = TopologyProjectSimple.objects.get(id=project_id)
        data = request.data
        
        device = NetworkDeviceSimple.objects.create(
            project=project,
            name=data['name'],
            device_type=data['device_type'],
            latitude=data['latitude'],
            longitude=data['longitude'],
            altitude=data.get('altitude'),
            properties=data.get('properties', {}),
            status=data.get('status', 'active')
        )
        
        # Recalcular bounds do projeto
        project.calculate_bounds_from_devices()
        
        return Response({
            'success': True,
            'device_id': str(device.id),
            'message': 'Dispositivo adicionado com sucesso'
        })
        
    except TopologyProjectSimple.DoesNotExist:
        return Response({
            'error': 'Projeto não encontrado'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'error': f'Erro ao adicionar dispositivo: {str(e)}'
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])  # Temporariamente AllowAny para testes
def create_simple_network_connection(request, project_id):
    """Cria conexão entre dispositivos"""
    try:
        project = TopologyProjectSimple.objects.get(id=project_id)
        data = request.data
        
        source_device = NetworkDeviceSimple.objects.get(id=data['source_device_id'])
        target_device = NetworkDeviceSimple.objects.get(id=data['target_device_id'])
        
        # Criar conexão
        connection = NetworkConnectionSimple(
            project=project,
            source_device=source_device,
            target_device=target_device,
            connection_type=data['connection_type'],
            properties=data.get('properties', {}),
            style_properties=data.get('style_properties', {})
        )
        
        # Definir caminho
        if data.get('path_coordinates'):
            # Caminho customizado fornecido
            connection.set_path_from_coordinates(data['path_coordinates'])
            connection.calculation_method = 'manual'
        else:
            # Criar linha reta entre dispositivos
            connection.create_straight_line_path()
        
        connection.save()
        
        return Response({
            'success': True,
            'connection_id': str(connection.id),
            'message': 'Conexão criada com sucesso',
            'length_meters': connection.length_meters
        })
        
    except TopologyProjectSimple.DoesNotExist:
        return Response({
            'error': 'Projeto não encontrado'
        }, status=status.HTTP_404_NOT_FOUND)
    except NetworkDeviceSimple.DoesNotExist:
        return Response({
            'error': 'Dispositivo não encontrado'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'error': f'Erro ao criar conexão: {str(e)}'
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([AllowAny])  # Temporariamente AllowAny para testes
def get_simple_project_geojson(request, project_id):
    """Retorna projeto em formato GeoJSON"""
    try:
        project = TopologyProjectSimple.objects.get(id=project_id)
        
        # Criar GeoJSON
        geojson = {
            'type': 'FeatureCollection',
            'features': []
        }
        
        # Adicionar dispositivos como pontos
        for device in project.devices.all():
            feature = {
                'type': 'Feature',
                'geometry': {
                    'type': 'Point',
                    'coordinates': [device.longitude, device.latitude]
                },
                'properties': {
                    'id': str(device.id),
                    'name': device.name,
                    'device_type': device.device_type,
                    'status': device.status,
                    'properties': device.properties
                }
            }
            geojson['features'].append(feature)
        
        # Adicionar conexões como linhas
        for connection in project.connections.all():
            if connection.path_coordinates:
                feature = connection.export_to_geojson()
                geojson['features'].append(feature)
        
        return Response(geojson)
        
    except TopologyProjectSimple.DoesNotExist:
        return Response({
            'error': 'Projeto não encontrado'
        }, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([AllowAny])  # Temporariamente AllowAny para testes
def get_simple_project_summary(request, project_id):
    """Retorna resumo do projeto"""
    try:
        project = TopologyProjectSimple.objects.get(id=project_id)
        
        devices = project.devices.all()
        connections = project.connections.all()
        
        # Estatísticas
        device_types = {}
        for device in devices:
            device_types[device.device_type] = device_types.get(device.device_type, 0) + 1
        
        connection_types = {}
        for connection in connections:
            connection_types[connection.connection_type] = connection_types.get(connection.connection_type, 0) + 1
        
        total_length = sum(conn.length_meters for conn in connections)
        
        return Response({
            'project': {
                'id': str(project.id),
                'name': project.name,
                'description': project.description,
                'center_latitude': project.center_latitude,
                'center_longitude': project.center_longitude,
                'zoom_level': project.zoom_level
            },
            'statistics': {
                'total_devices': devices.count(),
                'total_connections': connections.count(),
                'device_types': device_types,
                'connection_types': connection_types,
                'total_length_km': total_length / 1000
            }
        })
        
    except TopologyProjectSimple.DoesNotExist:
        return Response({
            'error': 'Projeto não encontrado'
        }, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([AllowAny])  # Temporariamente AllowAny para testes
def find_nearby_simple_devices(request):
    """Encontra dispositivos próximos a um ponto"""
    try:
        lat = float(request.GET.get('lat'))
        lng = float(request.GET.get('lng'))
        radius_km = float(request.GET.get('radius', 10))
        
        # Converter para metros
        radius_m = radius_km * 1000
        
        nearby_devices = []
        
        # Buscar em todos os projetos (pode ser otimizado)
        for device in NetworkDeviceSimple.objects.all():
            # Criar dispositivo temporário para cálculo
            temp_device = NetworkDeviceSimple(latitude=lat, longitude=lng)
            distance = temp_device.distance_to(device)
            
            if distance <= radius_m:
                nearby_devices.append({
                    'id': str(device.id),
                    'name': device.name,
                    'device_type': device.device_type,
                    'latitude': device.latitude,
                    'longitude': device.longitude,
                    'distance_km': distance / 1000,
                    'project_name': device.project.name
                })
        
        # Ordenar por distância
        nearby_devices.sort(key=lambda x: x['distance_km'])
        
        return Response({
            'nearby_devices': nearby_devices,
            'search_point': {'lat': lat, 'lng': lng},
            'radius_km': radius_km
        })
        
    except ValueError:
        return Response({
            'error': 'Parâmetros inválidos'
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([AllowAny])  # Temporariamente AllowAny para testes
def list_simple_projects(request):
    """Lista todos os projetos"""
    projects = TopologyProjectSimple.objects.all()
    
    project_list = []
    for project in projects:
        project_list.append({
            'id': str(project.id),
            'name': project.name,
            'description': project.description,
            'device_count': project.devices.count(),
            'connection_count': project.connections.count(),
            'created_at': project.created_at,
            'updated_at': project.updated_at
        })
    
    return Response({
        'projects': project_list
    })

# ViewSets para CRUD completo
class TopologyProjectSimpleViewSet(viewsets.ModelViewSet):
    """ViewSet para projetos de topologia simplificados"""
    queryset = TopologyProjectSimple.objects.all()
    permission_classes = [IsAuthenticated]
    
    def get_serializer_class(self):
        from rest_framework import serializers
        
        class TopologyProjectSimpleSerializer(serializers.ModelSerializer):
            class Meta:
                model = TopologyProjectSimple
                fields = '__all__'
        
        return TopologyProjectSimpleSerializer

class NetworkDeviceSimpleViewSet(viewsets.ModelViewSet):
    """ViewSet para dispositivos de rede simplificados"""
    queryset = NetworkDeviceSimple.objects.all()
    permission_classes = [IsAuthenticated]
    
    def get_serializer_class(self):
        from rest_framework import serializers
        
        class NetworkDeviceSimpleSerializer(serializers.ModelSerializer):
            class Meta:
                model = NetworkDeviceSimple
                fields = '__all__'
        
        return NetworkDeviceSimpleSerializer

class NetworkConnectionSimpleViewSet(viewsets.ModelViewSet):
    """ViewSet para conexões de rede simplificadas"""
    queryset = NetworkConnectionSimple.objects.all()
    permission_classes = [IsAuthenticated]
    
    def get_serializer_class(self):
        from rest_framework import serializers
        
        class NetworkConnectionSimpleSerializer(serializers.ModelSerializer):
            class Meta:
                model = NetworkConnectionSimple
                fields = '__all__'
        
        return NetworkConnectionSimpleSerializer
