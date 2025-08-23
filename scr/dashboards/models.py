import uuid
import json
from django.db import models
from django.contrib.auth.models import User
from django.core.serializers.json import DjangoJSONEncoder


class Dashboard(models.Model):
    """
    Model para armazenar dashboards/projetos de topologia
    """
    DASHBOARD_TYPES = [
        ('topology', 'Topology Manager'),
        ('network', 'Network Map'),
        ('custom', 'Custom Dashboard'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200, help_text="Nome do dashboard")
    description = models.TextField(blank=True, help_text="Descrição do dashboard")
    dashboard_type = models.CharField(
        max_length=20, 
        choices=DASHBOARD_TYPES, 
        default='topology',
        help_text="Tipo de dashboard"
    )
    
    # Configurações do mapa
    center_latitude = models.FloatField(default=-15.7942287, help_text="Latitude do centro do mapa")
    center_longitude = models.FloatField(default=-47.8821945, help_text="Longitude do centro do mapa")
    zoom_level = models.IntegerField(default=6, help_text="Nível de zoom do mapa")
    
    # Metadata e controle de acesso
    created_by = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='dashboards',
        help_text="Usuário que criou o dashboard"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_public = models.BooleanField(
        default=False, 
        help_text="Se verdadeiro, dashboard é visível para outros usuários"
    )
    
    # Campos JSON para dados extras
    extra_data = models.JSONField(
        default=dict, 
        blank=True,
        encoder=DjangoJSONEncoder,
        help_text="Dados extras em formato JSON"
    )
    
    class Meta:
        ordering = ['-updated_at']
        verbose_name = "Dashboard"
        verbose_name_plural = "Dashboards"
        
    def __str__(self):
        return f"{self.name} ({self.get_dashboard_type_display()})"
    
    @property
    def node_count(self):
        """Retorna número de nós no dashboard"""
        return self.nodes.count()
    
    @property 
    def connection_count(self):
        """Retorna número de conexões no dashboard"""
        return self.connections.count()


class DashboardNode(models.Model):
    """
    Model para nós/equipamentos no dashboard
    """
    NODE_TYPES = [
        ('router', 'Router'),
        ('switch', 'Switch'),
        ('server', 'Server'),
        ('firewall', 'Firewall'),
        ('access_point', 'Access Point'),
        ('load_balancer', 'Load Balancer'),
        ('gateway', 'Gateway'),
        ('other', 'Other'),
    ]
    
    STATUS_CHOICES = [
        ('online', 'Online'),
        ('offline', 'Offline'),
        ('warning', 'Warning'),
        ('critical', 'Critical'),
        ('unknown', 'Unknown'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    dashboard = models.ForeignKey(
        Dashboard, 
        on_delete=models.CASCADE, 
        related_name='nodes',
        help_text="Dashboard ao qual o nó pertence"
    )
    name = models.CharField(max_length=100, help_text="Nome do nó")
    node_type = models.CharField(
        max_length=20, 
        choices=NODE_TYPES,
        default='router',
        help_text="Tipo do nó"
    )
    
    # Posição geográfica
    latitude = models.FloatField(help_text="Latitude do nó")
    longitude = models.FloatField(help_text="Longitude do nó")
    
    # Propriedades do nó
    ip_address = models.GenericIPAddressField(
        null=True, 
        blank=True, 
        help_text="Endereço IP do nó"
    )
    status = models.CharField(
        max_length=10, 
        choices=STATUS_CHOICES,
        default='unknown',
        help_text="Status operacional do nó"
    )
    
    # Propriedades extras em JSON
    properties = models.JSONField(
        default=dict, 
        blank=True,
        encoder=DjangoJSONEncoder,
        help_text="Propriedades extras do nó em JSON"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
        verbose_name = "Dashboard Node"
        verbose_name_plural = "Dashboard Nodes"
        unique_together = ['dashboard', 'name']  # Nome único por dashboard
        
    def __str__(self):
        return f"{self.name} ({self.get_node_type_display()}) - {self.dashboard.name}"


class DashboardConnection(models.Model):
    """
    Model para conexões entre nós no dashboard
    """
    CONNECTION_TYPES = [
        ('fiber', 'Fiber Optic'),
        ('wireless', 'Wireless'),
        ('ethernet', 'Ethernet'),
        ('logical', 'Logical'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    dashboard = models.ForeignKey(
        Dashboard, 
        on_delete=models.CASCADE, 
        related_name='connections',
        help_text="Dashboard ao qual a conexão pertence"
    )
    source_node = models.ForeignKey(
        DashboardNode, 
        on_delete=models.CASCADE, 
        related_name='outgoing_connections',
        help_text="Nó de origem da conexão"
    )
    target_node = models.ForeignKey(
        DashboardNode, 
        on_delete=models.CASCADE, 
        related_name='incoming_connections',
        help_text="Nó de destino da conexão"
    )
    
    connection_type = models.CharField(
        max_length=20, 
        choices=CONNECTION_TYPES,
        default='ethernet',
        help_text="Tipo da conexão"
    )
    
    # Dados da rota
    path_data = models.JSONField(
        default=list, 
        blank=True,
        encoder=DjangoJSONEncoder,
        help_text="Coordenadas do caminho da conexão [[lat,lng], [lat,lng]]"
    )
    is_calculated = models.BooleanField(
        default=False,
        help_text="Se a rota foi calculada por vias terrestres"
    )
    distance_meters = models.FloatField(
        null=True, 
        blank=True, 
        help_text="Distância da conexão em metros"
    )
    
    # Propriedades da conexão
    bandwidth = models.CharField(
        max_length=50, 
        blank=True,
        help_text="Largura de banda da conexão (ex: '1 Gbps')"
    )
    
    # Propriedades extras em JSON
    properties = models.JSONField(
        default=dict, 
        blank=True,
        encoder=DjangoJSONEncoder,
        help_text="Propriedades extras da conexão em JSON"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['created_at']
        verbose_name = "Dashboard Connection"
        verbose_name_plural = "Dashboard Connections"
        unique_together = ['dashboard', 'source_node', 'target_node']  # Previne conexões duplicadas
        
    def __str__(self):
        return f"{self.source_node.name} → {self.target_node.name} ({self.get_connection_type_display()})"
    
    @property
    def distance_km(self):
        """Retorna distância em quilômetros"""
        if self.distance_meters:
            return round(self.distance_meters / 1000, 2)
        return None
    
    def save(self, *args, **kwargs):
        # Garantir que source e target estão no mesmo dashboard
        if self.source_node.dashboard != self.target_node.dashboard:
            raise ValueError("Source e target nodes devem pertencer ao mesmo dashboard")
        
        if not self.dashboard:
            self.dashboard = self.source_node.dashboard
            
        super().save(*args, **kwargs)