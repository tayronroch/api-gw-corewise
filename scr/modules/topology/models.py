from django.db import models
import json

class Equipment(models.Model):
    name = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField(unique=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.ip_address})"

class Link(models.Model):
    source = models.ForeignKey(Equipment, related_name='source_links', on_delete=models.CASCADE)
    target = models.ForeignKey(Equipment, related_name='target_links', on_delete=models.CASCADE)
    description = models.TextField(blank=True, null=True)
    ptp_ip = models.GenericIPAddressField(help_text="IP ponto a ponto da interface", blank=True, null=True)
    capacity_mbps = models.PositiveIntegerField(help_text="Capacidade do enlace em Mbps", blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.source} <-> {self.target}"

class LinkTrafficHistory(models.Model):
    link = models.ForeignKey(Link, related_name='traffic_history', on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    traffic_in_bps = models.BigIntegerField(help_text="Tráfego de entrada em bps")
    traffic_out_bps = models.BigIntegerField(help_text="Tráfego de saída em bps")

    class Meta:
        indexes = [
            models.Index(fields=['link', 'timestamp']),
        ]
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.link} @ {self.timestamp}"

# Novos modelos para topologias
class TopologyProject(models.Model):
    NODE_TYPES = [
        ('router', 'Roteador'),
        ('switch', 'Switch'),
        ('server', 'Servidor'),
        ('host', 'Host'),
        ('antenna', 'Antena'),
        ('building', 'Prédio'),
    ]
    
    id = models.CharField(max_length=50, primary_key=True)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    center_latitude = models.FloatField()
    center_longitude = models.FloatField()
    zoom = models.IntegerField(default=6)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name

class TopologyNode(models.Model):
    NODE_TYPES = [
        ('router', 'Roteador'),
        ('switch', 'Switch'),
        ('server', 'Servidor'),
        ('host', 'Host'),
        ('antenna', 'Antena'),
        ('building', 'Prédio'),
    ]
    
    STATUS_CHOICES = [
        ('online', 'Online'),
        ('offline', 'Offline'),
        ('warning', 'Warning'),
    ]
    
    id = models.CharField(max_length=50, primary_key=True)
    project = models.ForeignKey(TopologyProject, related_name='nodes', on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    node_type = models.CharField(max_length=20, choices=NODE_TYPES)
    latitude = models.FloatField()
    longitude = models.FloatField()
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    model = models.CharField(max_length=100, blank=True, null=True)
    vendor = models.CharField(max_length=100, blank=True, null=True)
    capacity = models.CharField(max_length=50, blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='online')
    connections = models.JSONField(default=list)  # Lista de IDs de conexões
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} ({self.get_node_type_display()})"

class TopologyConnection(models.Model):
    CONNECTION_TYPES = [
        ('fiber', 'Fibra Óptica'),
        ('wireless', 'Wireless'),
        ('ethernet', 'Ethernet'),
        ('logical', 'Lógica'),
    ]
    
    id = models.CharField(max_length=50, primary_key=True)
    project = models.ForeignKey(TopologyProject, related_name='connections', on_delete=models.CASCADE)
    source_node = models.ForeignKey(TopologyNode, related_name='source_connections', on_delete=models.CASCADE)
    target_node = models.ForeignKey(TopologyNode, related_name='target_connections', on_delete=models.CASCADE)
    connection_type = models.CharField(max_length=20, choices=CONNECTION_TYPES)
    bandwidth = models.CharField(max_length=50, blank=True, null=True)
    path = models.JSONField()  # Array de coordenadas [lat, lng]
    is_calculated = models.BooleanField(default=False)
    distance = models.FloatField(blank=True, null=True)  # Distância em metros
    length = models.FloatField(blank=True, null=True)
    latency = models.FloatField(blank=True, null=True)
    utilization = models.FloatField(blank=True, null=True)
    traffic_inbound = models.BigIntegerField(blank=True, null=True)
    traffic_outbound = models.BigIntegerField(blank=True, null=True)
    traffic_latency = models.FloatField(blank=True, null=True)
    color = models.CharField(max_length=7, default='#2196F3')  # Cor em hex
    width = models.IntegerField(default=3)
    opacity = models.FloatField(default=0.8)
    dash_array = models.CharField(max_length=20, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.source_node.name} <-> {self.target_node.name}"
    
    def get_path_distance(self):
        """Calcula a distância total do caminho em metros"""
        if not self.path or len(self.path) < 2:
            return 0
        
        total_distance = 0
        for i in range(1, len(self.path)):
            lat1, lng1 = self.path[i-1]
            lat2, lng2 = self.path[i]
            
            # Fórmula de Haversine
            import math
            R = 6371000  # Raio da Terra em metros
            d_lat = math.radians(lat2 - lat1)
            d_lng = math.radians(lng2 - lng1)
            
            a = (math.sin(d_lat/2) * math.sin(d_lat/2) +
                 math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
                 math.sin(d_lng/2) * math.sin(d_lng/2))
            c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
            
            total_distance += R * c
        
        return total_distance
