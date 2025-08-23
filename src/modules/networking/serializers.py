"""
Django REST Framework serializers para o app networking
Baseado na funcionalidade do l2vpn-master
"""
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    City, NetworkInterface, L2VPNConfiguration, 
    BGPConfiguration, OSPFConfiguration, NetworkConfigurationLog
)


class UserSerializer(serializers.ModelSerializer):
    """Serializer básico para usuários"""
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']


class CitySerializer(serializers.ModelSerializer):
    """Serializer para cidades - baseado na tabela 'cidades' do l2vpn-master"""
    class Meta:
        model = City
        fields = [
            'id', 'name', 'ip_address', 
            'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_ip_address(self, value):
        """Validar formato do IP"""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            raise serializers.ValidationError("Formato de IP inválido")


class NetworkInterfaceSerializer(serializers.ModelSerializer):
    """Serializer para interfaces de rede"""
    city_name = serializers.CharField(source='city.name', read_only=True)
    
    class Meta:
        model = NetworkInterface
        fields = [
            'id', 'name', 'city', 'city_name', 'interface_type',
            'is_active', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class L2VPNConfigurationSerializer(serializers.ModelSerializer):
    """Serializer para configurações L2VPN VPWS"""
    pe1_city_name = serializers.CharField(source='pe1_city.name', read_only=True)
    pe2_city_name = serializers.CharField(source='pe2_city.name', read_only=True)
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = L2VPNConfiguration
        fields = [
            'id', 'pe1_city', 'pe1_city_name', 'pe2_city', 'pe2_city_name',
            'pe1_mode', 'pe2_mode',
            # PE1 fields
            'pe1_vpws_group_name', 'pe1_vpn_id', 'pe1_neighbor_ip', 'pe1_pw_id',
            'pe1_access_interface', 'pe1_dot1q', 'pe1_pw_vlan', 'pe1_neighbor_targeted_ip',
            # PE2 fields  
            'pe2_vpws_group_name', 'pe2_vpn_id', 'pe2_neighbor_ip', 'pe2_pw_id',
            'pe2_access_interface', 'pe2_dot1q', 'pe2_pw_vlan', 'pe2_neighbor_targeted_ip',
            # Metadata
            'description', 'is_active', 'created_by', 'created_by_username',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate(self, data):
        """Validações customizadas"""
        # Validar que PE1 e PE2 são diferentes
        if data.get('pe1_city') and data.get('pe2_city'):
            if data['pe1_city'].id == data['pe2_city'].id:
                raise serializers.ValidationError(
                    "As cidades PE1 e PE2 devem ser diferentes"
                )
        
        # Validar IPs
        import ipaddress
        for field in ['pe1_neighbor_ip', 'pe2_neighbor_ip', 'pe1_neighbor_targeted_ip', 'pe2_neighbor_targeted_ip']:
            if data.get(field):
                try:
                    ipaddress.ip_address(data[field])
                except ValueError:
                    raise serializers.ValidationError(f"Campo {field} deve ter um IP válido")
        
        return data


class BGPConfigurationSerializer(serializers.ModelSerializer):
    """Serializer para configurações BGP"""
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = BGPConfiguration
        fields = [
            'id', 'router_ip', 'vlan', 'client_name',
            'subnet_v4', 'client_network_v4', 'v4_size',
            'subnet_v6', 'client_network_v6', 'v6_size', 
            'client_asn', 'description', 'is_active',
            'created_by', 'created_by_username', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_router_ip(self, value):
        """Validar IP do roteador"""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            raise serializers.ValidationError("IP do roteador inválido")

    def validate_client_asn(self, value):
        """Validar ASN do cliente"""
        if not (1 <= value <= 4294967295):  # Range válido para ASN
            raise serializers.ValidationError("ASN deve estar entre 1 e 4294967295")
        return value

    def validate(self, data):
        """Validações de redes"""
        import ipaddress
        
        # Validar subnets IPv4
        if data.get('subnet_v4'):
            try:
                ipaddress.IPv4Network(data['subnet_v4'], strict=False)
            except ValueError:
                raise serializers.ValidationError("Subnet IPv4 inválida")
        
        if data.get('client_network_v4'):
            try:
                ipaddress.IPv4Network(data['client_network_v4'], strict=False)
            except ValueError:
                raise serializers.ValidationError("Rede IPv4 do cliente inválida")
        
        # Validar subnets IPv6
        if data.get('subnet_v6'):
            try:
                ipaddress.IPv6Network(data['subnet_v6'], strict=False)
            except ValueError:
                raise serializers.ValidationError("Subnet IPv6 inválida")
        
        if data.get('client_network_v6'):
            try:
                ipaddress.IPv6Network(data['client_network_v6'], strict=False)
            except ValueError:
                raise serializers.ValidationError("Rede IPv6 do cliente inválida")
        
        return data


class OSPFConfigurationSerializer(serializers.ModelSerializer):
    """Serializer para configurações OSPF"""
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = OSPFConfiguration
        fields = [
            'id', 'router_ip', 'process_id', 'router_id', 'area_id',
            'interface', 'cost', 'description', 'is_active',
            'created_by', 'created_by_username', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_router_ip(self, value):
        """Validar IP do roteador"""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            raise serializers.ValidationError("IP do roteador inválido")

    def validate_router_id(self, value):
        """Validar Router ID OSPF"""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            raise serializers.ValidationError("Router ID deve ser um IP válido")

    def validate_process_id(self, value):
        """Validar Process ID OSPF"""
        if not (1 <= value <= 65535):
            raise serializers.ValidationError("Process ID deve estar entre 1 e 65535")
        return value

    def validate_cost(self, value):
        """Validar custo OSPF"""
        if not (1 <= value <= 65535):
            raise serializers.ValidationError("Custo deve estar entre 1 e 65535")
        return value


class NetworkConfigurationLogSerializer(serializers.ModelSerializer):
    """Serializer para logs de configuração de rede"""
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    l2vpn_config_id = serializers.CharField(source='l2vpn_config.id', read_only=True)
    bgp_config_id = serializers.CharField(source='bgp_config.id', read_only=True)
    ospf_config_id = serializers.CharField(source='ospf_config.id', read_only=True)
    
    class Meta:
        model = NetworkConfigurationLog
        fields = [
            'id', 'operation_type', 'status', 'target_ip', 'username',
            'commands_executed', 'output', 'error_message', 'execution_time',
            'started_at', 'finished_at',
            'l2vpn_config', 'l2vpn_config_id',
            'bgp_config', 'bgp_config_id', 
            'ospf_config', 'ospf_config_id',
            'created_by', 'created_by_username'
        ]
        read_only_fields = [
            'id', 'started_at', 'finished_at', 'execution_time',
            'l2vpn_config_id', 'bgp_config_id', 'ospf_config_id'
        ]


# ==========================================
# Serializers para compatibilidade com l2vpn-master
# ==========================================

class CompatibilityL2VPNSerializer(serializers.Serializer):
    """Serializer para dados de entrada compatíveis com l2vpn-master"""
    # Campos do formulário original
    cidade_pe1 = serializers.CharField(max_length=100)
    cidade_pe2 = serializers.CharField(max_length=100)
    login = serializers.CharField(max_length=50)
    senha = serializers.CharField(max_length=50, write_only=True)
    
    # PE1 fields
    vpws_group_name_pe1 = serializers.CharField(max_length=100)
    vpn_id_pe1 = serializers.CharField(max_length=50)
    neighbor_ip_pe1 = serializers.IPAddressField()
    pw_id_pe1 = serializers.CharField(max_length=50)
    neighbor_targeted_ip_pe1 = serializers.IPAddressField()
    empresa_pe1 = serializers.CharField(max_length=100, required=False)
    numero_pe1 = serializers.CharField(max_length=50, required=False)
    dot1q_pe1 = serializers.CharField(max_length=50, required=False)
    pw_vlan_pe1 = serializers.CharField(max_length=50, required=False)
    access_pe1 = serializers.CharField(max_length=20, required=False)
    vlan_selective_pe1 = serializers.CharField(max_length=20, required=False)
    
    # PE2 fields
    vpws_group_name_pe2 = serializers.CharField(max_length=100)
    vpn_id_pe2 = serializers.CharField(max_length=50)
    neighbor_ip_pe2 = serializers.IPAddressField()
    pw_id_pe2 = serializers.CharField(max_length=50)
    neighbor_targeted_ip_pe2 = serializers.IPAddressField()
    empresa_pe2 = serializers.CharField(max_length=100, required=False)
    numero_pe2 = serializers.CharField(max_length=50, required=False)
    dot1q_pe2 = serializers.CharField(max_length=50, required=False)
    pw_vlan_pe2 = serializers.CharField(max_length=50, required=False)
    access_pe2 = serializers.CharField(max_length=20, required=False)
    vlan_selective_pe2 = serializers.CharField(max_length=20, required=False)


class CompatibilityBGPSerializer(serializers.Serializer):
    """Serializer para dados BGP compatíveis com l2vpn-master"""
    ip_roteador = serializers.IPAddressField()
    login = serializers.CharField(max_length=50)
    senha = serializers.CharField(max_length=50, write_only=True)
    vlan = serializers.CharField(max_length=50)
    cliente = serializers.CharField(max_length=100)
    subnet_v4 = serializers.CharField(max_length=50)
    subnet_v6 = serializers.CharField(max_length=50)
    asn_cliente = serializers.CharField(max_length=20)
    rede_v4_cliente = serializers.CharField(max_length=50)
    rede_v6_cliente = serializers.CharField(max_length=50)
    tamanho_v4 = serializers.CharField(max_length=10)
    tamanho_v6 = serializers.CharField(max_length=10)


class CompatibilityOSPFSerializer(serializers.Serializer):
    """Serializer para dados OSPF compatíveis com l2vpn-master"""
    login = serializers.CharField(max_length=50)
    senha = serializers.CharField(max_length=50, write_only=True)
    configs = serializers.ListField(
        child=serializers.DictField(),
        allow_empty=False
    )

    def validate_configs(self, value):
        """Validar estrutura das configurações OSPF"""
        for config in value:
            required_fields = ['ip']
            for field in required_fields:
                if field not in config:
                    raise serializers.ValidationError(f"Campo '{field}' é obrigatório em cada configuração")
        return value