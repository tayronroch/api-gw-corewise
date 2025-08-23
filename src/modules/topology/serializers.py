from rest_framework import serializers
from .models import Equipment, Link, LinkTrafficHistory, TopologyProject, TopologyNode, TopologyConnection

class EquipmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Equipment
        fields = '__all__'

class LinkSerializer(serializers.ModelSerializer):
    source = EquipmentSerializer(read_only=True)
    target = EquipmentSerializer(read_only=True)
    
    class Meta:
        model = Link
        fields = '__all__'

class LinkTrafficHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = LinkTrafficHistory
        fields = '__all__'

# Novos serializers para topologias
class TopologyNodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = TopologyNode
        fields = '__all__'

class TopologyNodeCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = TopologyNode
        fields = ['id', 'name', 'node_type', 'latitude', 'longitude', 'ip_address', 'model', 'vendor', 'capacity', 'status', 'connections']

class TopologyConnectionSerializer(serializers.ModelSerializer):
    source_node = TopologyNodeSerializer(read_only=True)
    target_node = TopologyNodeSerializer(read_only=True)
    
    class Meta:
        model = TopologyConnection
        fields = '__all__'

class TopologyConnectionCreateSerializer(serializers.ModelSerializer):
    source_node = serializers.CharField(required=False)  # Não validar durante criação
    target_node = serializers.CharField(required=False)  # Não validar durante criação
    
    class Meta:
        model = TopologyConnection
        fields = ['id', 'source_node', 'target_node', 'connection_type', 'bandwidth', 'path', 'is_calculated', 'distance', 'length', 'latency', 'utilization', 'traffic_inbound', 'traffic_outbound', 'traffic_latency', 'color', 'width', 'opacity', 'dash_array']

class TopologyProjectSerializer(serializers.ModelSerializer):
    nodes = TopologyNodeSerializer(many=True, read_only=True)
    connections = TopologyConnectionSerializer(many=True, read_only=True)
    
    class Meta:
        model = TopologyProject
        fields = '__all__'

# Serializer para criar/atualizar projetos completos
class TopologyProjectCreateSerializer(serializers.ModelSerializer):
    nodes = TopologyNodeCreateSerializer(many=True, required=False)
    connections = TopologyConnectionCreateSerializer(many=True, required=False)
    
    class Meta:
        model = TopologyProject
        fields = '__all__'
    
    def create(self, validated_data):
        nodes_data = validated_data.pop('nodes', [])
        connections_data = validated_data.pop('connections', [])
        
        # Criar o projeto
        project = TopologyProject.objects.create(**validated_data)
        
        # Criar os nós
        created_nodes = {}
        for node_data in nodes_data:
            node = TopologyNode.objects.create(project=project, **node_data)
            created_nodes[node_data['id']] = node
        
        # Criar as conexões
        for connection_data in connections_data:
            source_id = connection_data.pop('source_node')
            target_id = connection_data.pop('target_node')
            
            # Primeiro tentar nós criados na mesma operação
            source_node = created_nodes.get(source_id)
            target_node = created_nodes.get(target_id)
            
            # Se não encontrou, buscar nós existentes no banco
            if not source_node:
                try:
                    source_node = TopologyNode.objects.get(id=source_id)
                except TopologyNode.DoesNotExist:
                    print(f"DEBUG: Nó source não encontrado: {source_id}")
                    continue
                    
            if not target_node:
                try:
                    target_node = TopologyNode.objects.get(id=target_id)
                except TopologyNode.DoesNotExist:
                    print(f"DEBUG: Nó target não encontrado: {target_id}")
                    continue
            
            if source_node and target_node:
                print(f"DEBUG: Criando conexão entre {source_node.name} e {target_node.name}")
                TopologyConnection.objects.create(
                    project=project,
                    source_node=source_node,
                    target_node=target_node,
                    **connection_data
                )
        
        return project
    
    def update(self, instance, validated_data):
        nodes_data = validated_data.pop('nodes', [])
        connections_data = validated_data.pop('connections', [])
        
        # Atualizar o projeto
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Limpar nós e conexões existentes
        instance.nodes.all().delete()
        instance.connections.all().delete()
        
        # Recriar nós
        created_nodes = {}
        for node_data in nodes_data:
            node = TopologyNode.objects.create(project=instance, **node_data)
            created_nodes[node_data['id']] = node
        
        # Recriar conexões
        for connection_data in connections_data:
            source_id = connection_data.pop('source_node')
            target_id = connection_data.pop('target_node')
            
            # Primeiro tentar nós criados na mesma operação
            source_node = created_nodes.get(source_id)
            target_node = created_nodes.get(target_id)
            
            # Se não encontrou, buscar nós existentes no banco
            if not source_node:
                try:
                    source_node = TopologyNode.objects.get(id=source_id)
                except TopologyNode.DoesNotExist:
                    print(f"DEBUG: Nó source não encontrado: {source_id}")
                    continue
                    
            if not target_node:
                try:
                    target_node = TopologyNode.objects.get(id=target_id)
                except TopologyNode.DoesNotExist:
                    print(f"DEBUG: Nó target não encontrado: {target_id}")
                    continue
            
            if source_node and target_node:
                print(f"DEBUG: Criando conexão entre {source_node.name} e {target_node.name}")
                TopologyConnection.objects.create(
                    project=instance,
                    source_node=source_node,
                    target_node=target_node,
                    **connection_data
                )
        
        return instance
