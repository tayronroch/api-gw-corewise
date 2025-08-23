from django.shortcuts import render
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.http import JsonResponse
from .models import Equipment, Link, LinkTrafficHistory, TopologyProject, TopologyNode, TopologyConnection
from .serializers import (
    EquipmentSerializer, LinkSerializer, LinkTrafficHistorySerializer,
    TopologyProjectSerializer, TopologyProjectCreateSerializer,
    TopologyNodeSerializer, TopologyConnectionSerializer
)
from .services import calculate_percentile95
import json

# Views existentes
class EquipmentViewSet(viewsets.ModelViewSet):
    queryset = Equipment.objects.all()
    serializer_class = EquipmentSerializer

class LinkViewSet(viewsets.ModelViewSet):
    queryset = Link.objects.all()
    serializer_class = LinkSerializer

class LinkTrafficHistoryViewSet(viewsets.ModelViewSet):
    queryset = LinkTrafficHistory.objects.all()
    serializer_class = LinkTrafficHistorySerializer

# Novas views para topologias
class TopologyProjectViewSet(viewsets.ModelViewSet):
    queryset = TopologyProject.objects.all()
    serializer_class = TopologyProjectSerializer
    permission_classes = [IsAuthenticated]
    
    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return TopologyProjectCreateSerializer
        return TopologyProjectSerializer

class TopologyNodeViewSet(viewsets.ModelViewSet):
    queryset = TopologyNode.objects.all()
    serializer_class = TopologyNodeSerializer
    permission_classes = [IsAuthenticated]

class TopologyConnectionViewSet(viewsets.ModelViewSet):
    queryset = TopologyConnection.objects.all()
    serializer_class = TopologyConnectionSerializer
    permission_classes = [IsAuthenticated]

# API views para funcionalidades específicas
@api_view(['GET'])
@permission_classes([AllowAny])  # Temporarily allow any for testing
def get_topology_projects(request):
    """Lista todos os projetos de topologia do usuário"""
    projects = TopologyProject.objects.all().order_by('-updated_at')
    serializer = TopologyProjectSerializer(projects, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([AllowAny])  # Temporarily allow any for testing
def get_topology_project(request, project_id):
    """Obtém um projeto específico com todos os seus dados"""
    try:
        project = TopologyProject.objects.get(id=project_id)
        serializer = TopologyProjectSerializer(project)
        return Response(serializer.data)
    except TopologyProject.DoesNotExist:
        return Response(
            {'error': 'Projeto não encontrado'}, 
            status=status.HTTP_404_NOT_FOUND
        )

@api_view(['POST'])
@permission_classes([AllowAny])  # Temporarily allow any for testing
def save_topology_project(request):
    """Salva um projeto completo de topologia"""
    try:
        data = request.data
        
        # Validação básica dos dados
        if not data.get('id'):
            return Response({
                'error': 'ID do projeto é obrigatório'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not data.get('name'):
            return Response({
                'error': 'Nome do projeto é obrigatório'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not data.get('center') or not data.get('center', {}).get('latitude') or not data.get('center', {}).get('longitude'):
            return Response({
                'error': 'Coordenadas do centro são obrigatórias'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Preparar dados para o serializer
        project_data = {
            'id': data.get('id'),
            'name': data.get('name'),
            'description': data.get('description', ''),
            'center_latitude': data.get('center', {}).get('latitude'),
            'center_longitude': data.get('center', {}).get('longitude'),
            'zoom': data.get('zoom', 6),
        }
        
        # Preparar nós
        nodes_data = []
        for node in data.get('nodes', []):
            node_data = {
                'id': node['id'],
                'name': node['name'],
                'node_type': node['type'],
                'latitude': node['position']['latitude'],
                'longitude': node['position']['longitude'],
                'ip_address': node.get('properties', {}).get('ipAddress'),
                'model': node.get('properties', {}).get('model'),
                'vendor': node.get('properties', {}).get('vendor'),
                'capacity': node.get('properties', {}).get('capacity'),
                'status': node.get('properties', {}).get('status', 'online'),
                'connections': node.get('connections', []),
            }
            nodes_data.append(node_data)
        
        # Preparar conexões
        connections_data = []
        for connection in data.get('connections', []):
            connection_data = {
                'id': connection['id'],
                'source_node': connection['sourceId'],
                'target_node': connection['targetId'],
                'connection_type': connection['type'],
                'bandwidth': connection.get('bandwidth'),
                'path': connection['path'],
                'is_calculated': connection.get('isCalculated', False),
                'distance': connection.get('distance'),
                'length': connection.get('properties', {}).get('length'),
                'latency': connection.get('properties', {}).get('latency'),
                'utilization': connection.get('properties', {}).get('utilization'),
                'traffic_inbound': connection.get('properties', {}).get('traffic', {}).get('inbound'),
                'traffic_outbound': connection.get('properties', {}).get('traffic', {}).get('outbound'),
                'traffic_latency': connection.get('properties', {}).get('traffic', {}).get('latency'),
                'color': connection.get('style', {}).get('color', '#2196F3'),
                'width': connection.get('style', {}).get('width', 3),
                'opacity': connection.get('style', {}).get('opacity', 0.8),
                'dash_array': connection.get('style', {}).get('dashArray'),
            }
            connections_data.append(connection_data)
        
        # Verificar se o projeto já existe
        project_id = project_data['id']
        try:
            existing_project = TopologyProject.objects.get(id=project_id)
            serializer = TopologyProjectCreateSerializer(existing_project, data={
                **project_data,
                'nodes': nodes_data,
                'connections': connections_data
            })
        except TopologyProject.DoesNotExist:
            serializer = TopologyProjectCreateSerializer(data={
                **project_data,
                'nodes': nodes_data,
                'connections': connections_data
            })
        
        if serializer.is_valid():
            project = serializer.save()
            return Response({
                'success': True,
                'message': 'Projeto salvo com sucesso',
                'project': TopologyProjectSerializer(project).data
            })
        else:
            print(f"DEBUG BACKEND: Erros de validação detalhados: {serializer.errors}")
            return Response({
                'error': 'Dados inválidos',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        return Response({
            'error': f'Erro ao salvar projeto: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PUT', 'PATCH'])
@permission_classes([AllowAny])  # Temporarily allow any for testing
def update_topology_project(request, project_id):
    """Atualiza um projeto de topologia existente"""
    try:
        project = TopologyProject.objects.get(id=project_id)
        data = request.data
        
        # Validar dados obrigatórios
        if not data.get('name'):
            return Response({
                'error': 'Nome do projeto é obrigatório'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Atualizar campos do projeto
        project.name = data.get('name', project.name)
        project.description = data.get('description', project.description)
        
        if data.get('center'):
            project.center_latitude = data['center'].get('latitude', project.center_latitude)
            project.center_longitude = data['center'].get('longitude', project.center_longitude)
        
        if data.get('zoom') is not None:
            project.zoom = data['zoom']
        
        project.save()
        
        return Response({
            'success': True,
            'message': 'Projeto atualizado com sucesso',
            'project': TopologyProjectSerializer(project).data
        })
        
    except TopologyProject.DoesNotExist:
        return Response(
            {'error': 'Projeto não encontrado'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response({
            'error': f'Erro ao atualizar projeto: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE'])
@permission_classes([AllowAny])  # Temporarily allow any for testing
def delete_topology_project(request, project_id):
    """Deleta um projeto de topologia"""
    try:
        project = TopologyProject.objects.get(id=project_id)
        project.delete()
        return Response({
            'success': True,
            'message': 'Projeto deletado com sucesso'
        })
    except TopologyProject.DoesNotExist:
        return Response(
            {'error': 'Projeto não encontrado'}, 
            status=status.HTTP_404_NOT_FOUND
        )

@api_view(['POST'])
@permission_classes([AllowAny])  # Temporarily allow any for testing
def save_topology_nodes(request):
    """Salva apenas os nós de topologia para um projeto existente"""
    try:
        data = request.data
        
        # Validar dados obrigatórios
        project_id = data.get('project_id')
        nodes = data.get('nodes', [])
        
        if not project_id:
            return Response({
                'error': 'ID do projeto é obrigatório'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verificar se o projeto existe
        try:
            project = TopologyProject.objects.get(id=project_id)
        except TopologyProject.DoesNotExist:
            return Response({
                'error': 'Projeto não encontrado'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Deletar nós existentes do projeto
        project.nodes.all().delete()
        
        # Criar novos nós
        created_nodes = []
        for node_data in nodes:
            try:
                # Criar nó
                node = TopologyNode.objects.create(
                    project=project,
                    id=node_data['id'],
                    name=node_data['name'],
                    node_type=node_data['node_type'],
                    latitude=node_data['latitude'],
                    longitude=node_data['longitude'],
                    ip_address=node_data.get('ip_address'),
                    model=node_data.get('model'),
                    vendor=node_data.get('vendor'),
                    capacity=node_data.get('capacity'),
                    status=node_data.get('status', 'online'),
                    connections=node_data.get('connections', []),
                )
                created_nodes.append(node)
                
            except Exception as e:
                return Response({
                    'error': f'Erro ao criar nó: {str(e)}'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({
            'success': True,
            'message': f'{len(created_nodes)} nós salvos com sucesso',
            'nodes_count': len(created_nodes)
        })
        
    except Exception as e:
        return Response({
            'error': f'Erro ao salvar nós: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])  # Temporarily allow any for testing
def save_topology_connections(request):
    """Salva apenas as conexões de topologia para um projeto existente"""
    try:
        data = request.data
        
        # Validar dados obrigatórios
        project_id = data.get('project_id')
        connections = data.get('connections', [])
        
        if not project_id:
            return Response({
                'error': 'ID do projeto é obrigatório'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verificar se o projeto existe
        try:
            project = TopologyProject.objects.get(id=project_id)
        except TopologyProject.DoesNotExist:
            return Response({
                'error': 'Projeto não encontrado'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Deletar conexões existentes do projeto
        project.connections.all().delete()
        
        # Criar novas conexões
        created_connections = []
        for connection_data in connections:
            try:
                # Buscar nós source e target
                source_node = TopologyNode.objects.get(id=connection_data['sourceId'])
                target_node = TopologyNode.objects.get(id=connection_data['targetId'])
                
                # Criar conexão
                connection = TopologyConnection.objects.create(
                    project=project,
                    id=connection_data['id'],
                    source_node=source_node,
                    target_node=target_node,
                    connection_type=connection_data['type'],
                    bandwidth=connection_data.get('bandwidth'),
                    path=connection_data['path'],
                    is_calculated=connection_data.get('isCalculated', False),
                    distance=connection_data.get('distance'),
                    length=connection_data.get('properties', {}).get('length'),
                    latency=connection_data.get('properties', {}).get('latency'),
                    utilization=connection_data.get('properties', {}).get('utilization'),
                    traffic_inbound=connection_data.get('properties', {}).get('traffic', {}).get('inbound'),
                    traffic_outbound=connection_data.get('properties', {}).get('traffic', {}).get('outbound'),
                    traffic_latency=connection_data.get('properties', {}).get('traffic', {}).get('latency'),
                    color=connection_data.get('style', {}).get('color', '#2196F3'),
                    width=connection_data.get('style', {}).get('width', 3),
                    opacity=connection_data.get('style', {}).get('opacity', 0.8),
                    dash_array=connection_data.get('style', {}).get('dashArray'),
                )
                created_connections.append(connection)
                
            except TopologyNode.DoesNotExist:
                return Response({
                    'error': f'Nó não encontrado: {connection_data.get("sourceId")} ou {connection_data.get("targetId")}'
                }, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({
                    'error': f'Erro ao criar conexão: {str(e)}'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({
            'success': True,
            'message': f'{len(created_connections)} conexões salvas com sucesso',
            'connections_count': len(created_connections),
            'calculated_routes': len([c for c in created_connections if c.is_calculated])
        })
        
    except Exception as e:
        return Response({
            'error': f'Erro ao salvar conexões: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Views existentes mantidas
def link_traffic_percentile95(request, link_id):
    try:
        link = Link.objects.get(id=link_id)
        percentile_value = calculate_percentile95(link)
        return JsonResponse({'percentile_95': percentile_value})
    except Link.DoesNotExist:
        return JsonResponse({'error': 'Link não encontrado'}, status=404)

class TopologyAPIView(viewsets.ViewSet):
    def list(self, request):
        # Implementação para API de topologia
        return Response({'message': 'Topology API'})

class NetworkMapView(viewsets.ViewSet):
    def list(self, request):
        # Implementação para API de mapa de rede
        return Response({'message': 'Network Map API'})
