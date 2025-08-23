from django.db import models
from django.contrib.auth.models import User
import uuid
from django.core.validators import validate_ipv4_address, validate_ipv6_address


class City(models.Model):
    """Modelo para cidades com roteadores"""
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Cidade"
        verbose_name_plural = "Cidades"
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.ip_address})"


class NetworkInterface(models.Model):
    """Interfaces de rede disponíveis"""
    INTERFACE_TYPES = [
        ('gigabit', 'Gigabit Ethernet'),
        ('ten-gigabit', 'Ten Gigabit'),
        ('forty-gigabit', 'Forty Gigabit'),
        ('twenty-five-gigabit', 'Twenty Five Gigabit'),
        ('hundred-gigabit', 'Hundred Gigabit'),
        ('lag', 'Link Aggregation Group'),
    ]

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    interface_type = models.CharField(max_length=20, choices=INTERFACE_TYPES, default='gigabit')
    city = models.ForeignKey(City, on_delete=models.CASCADE, related_name='interfaces')
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Interface de Rede"
        verbose_name_plural = "Interfaces de Rede"

    def __str__(self):
        return f"{self.name} - {self.city.name}"


class L2VPNConfiguration(models.Model):
    """Configurações L2VPN VPWS"""
    L2VPN_MODES = [
        ('qinq', 'QinQ'),
        ('access', 'Access'),
        ('vlan-selective', 'VLAN Selective'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Cidades PE
    pe1_city = models.ForeignKey(City, on_delete=models.CASCADE, related_name='l2vpn_pe1_configs')
    pe2_city = models.ForeignKey(City, on_delete=models.CASCADE, related_name='l2vpn_pe2_configs')
    
    # Modo L2VPN
    pe1_mode = models.CharField(max_length=20, choices=L2VPN_MODES, default='qinq')
    pe2_mode = models.CharField(max_length=20, choices=L2VPN_MODES, default='qinq')
    
    # Parâmetros PE1
    pe1_vpws_group_name = models.CharField(max_length=100)
    pe1_vpn_id = models.CharField(max_length=50)
    pe1_neighbor_ip = models.GenericIPAddressField()
    pe1_pw_id = models.CharField(max_length=50)
    pe1_access_interface = models.CharField(max_length=100)
    pe1_dot1q = models.CharField(max_length=10, blank=True, null=True)
    pe1_pw_vlan = models.CharField(max_length=10, blank=True, null=True)
    pe1_neighbor_targeted_ip = models.GenericIPAddressField()
    
    # Parâmetros PE2
    pe2_vpws_group_name = models.CharField(max_length=100)
    pe2_vpn_id = models.CharField(max_length=50)
    pe2_neighbor_ip = models.GenericIPAddressField()
    pe2_pw_id = models.CharField(max_length=50)
    pe2_access_interface = models.CharField(max_length=100)
    pe2_dot1q = models.CharField(max_length=10, blank=True, null=True)
    pe2_pw_vlan = models.CharField(max_length=10, blank=True, null=True)
    pe2_neighbor_targeted_ip = models.GenericIPAddressField()
    
    # Metadados
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    description = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Configuração L2VPN"
        verbose_name_plural = "Configurações L2VPN"

    def __str__(self):
        return f"L2VPN {self.pe1_city.name} <-> {self.pe2_city.name}"


class BGPConfiguration(models.Model):
    """Configurações BGP"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Dados do roteador
    router_ip = models.GenericIPAddressField()
    vlan = models.CharField(max_length=10)
    client_name = models.CharField(max_length=255)
    
    # Configurações IPv4
    subnet_v4 = models.CharField(max_length=20, help_text="Formato: 10.10.10.0/30")
    client_network_v4 = models.CharField(max_length=20, help_text="Formato: 170.80.80.0/22")
    v4_size = models.IntegerField(default=24)
    
    # Configurações IPv6
    subnet_v6 = models.CharField(max_length=50, help_text="Formato: 2001:db8::/126")
    client_network_v6 = models.CharField(max_length=50, help_text="Formato: 2804:3768::/32")
    v6_size = models.IntegerField(default=48)
    
    # ASN
    client_asn = models.IntegerField(help_text="Autonomous System Number do cliente")
    
    # Metadados
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    description = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Configuração BGP"
        verbose_name_plural = "Configurações BGP"

    def __str__(self):
        return f"BGP {self.client_name} - AS{self.client_asn}"


class OSPFConfiguration(models.Model):
    """Configurações OSPF"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Parâmetros OSPF
    router_ip = models.GenericIPAddressField()
    process_id = models.IntegerField(default=1)
    router_id = models.GenericIPAddressField(protocol='IPv4')
    area_id = models.CharField(max_length=20, default='0')
    interface = models.CharField(max_length=100)
    cost = models.IntegerField(default=100, help_text="Interface cost (1-65535)")
    
    # Metadados
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    description = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Configuração OSPF"
        verbose_name_plural = "Configurações OSPF"

    def __str__(self):
        return f"OSPF {self.router_id} - Area {self.area_id}"


class NetworkConfigurationLog(models.Model):
    """Log de execuções de configuração"""
    STATUS_CHOICES = [
        ('pending', 'Pendente'),
        ('running', 'Executando'),
        ('success', 'Sucesso'),
        ('failed', 'Falhou'),
        ('cancelled', 'Cancelado'),
    ]

    OPERATION_TYPES = [
        ('l2vpn', 'L2VPN Configuration'),
        ('bgp', 'BGP Configuration'),
        ('ospf', 'OSPF Configuration'),
        ('commit', 'Commit Configuration'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Metadados da operação
    operation_type = models.CharField(max_length=20, choices=OPERATION_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    target_ip = models.GenericIPAddressField(null=True, blank=True)
    username = models.CharField(max_length=100)
    
    # Dados da execução
    commands_executed = models.JSONField(default=list)
    output = models.TextField(blank=True, null=True)
    error_message = models.TextField(blank=True, null=True)
    execution_time = models.FloatField(null=True, blank=True)
    
    # Relações
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    l2vpn_config = models.ForeignKey(L2VPNConfiguration, on_delete=models.SET_NULL, null=True, blank=True)
    bgp_config = models.ForeignKey(BGPConfiguration, on_delete=models.SET_NULL, null=True, blank=True)
    ospf_config = models.ForeignKey(OSPFConfiguration, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Timestamps
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Log de Configuração"
        verbose_name_plural = "Logs de Configuração"
        ordering = ['-started_at']

    def __str__(self):
        return f"{self.operation_type.upper()} - {self.status} - {self.started_at}"