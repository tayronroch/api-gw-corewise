"""
Modelos simplificados para topologia de rede sem dependências do GeoDjango
Usa campos de latitude/longitude normais em vez de geometrias espaciais
"""
from django.db import models
import uuid
import json
import math

class TopologyProjectSimple(models.Model):
    """Projeto de topologia simplificado"""
    
    ZOOM_CHOICES = [(i, str(i)) for i in range(1, 19)]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    
    # Coordenadas centrais (simples)
    center_latitude = models.FloatField(help_text="Latitude central do projeto")
    center_longitude = models.FloatField(help_text="Longitude central do projeto")
    zoom_level = models.IntegerField(choices=ZOOM_CHOICES, default=10)
    
    # Metadados
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'topology_projects_simple'
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return self.name
    
    def calculate_bounds_from_devices(self):
        """Calcula limites automaticamente baseado nos dispositivos"""
        devices = self.devices.all()
        if devices.exists():
            lats = [d.latitude for d in devices]
            lngs = [d.longitude for d in devices]
            
            if lats and lngs:
                min_lat, max_lat = min(lats), max(lats)
                min_lng, max_lng = min(lngs), max(lngs)
                
                # Adicionar margem
                margin = 0.01  # ~1km de margem
                self.center_latitude = (min_lat + max_lat) / 2
                self.center_longitude = (min_lng + max_lng) / 2
                self.save()


class NetworkDeviceSimple(models.Model):
    """Dispositivo de rede com localização simples"""
    
    DEVICE_TYPES = [
        ('router', 'Roteador'),
        ('switch', 'Switch'),
        ('server', 'Servidor'),
        ('host', 'Host'),
        ('antenna', 'Antena'),
        ('building', 'Prédio'),
        ('datacenter', 'Data Center'),
        ('pop', 'Ponto de Presença'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Ativo'),
        ('inactive', 'Inativo'),
        ('maintenance', 'Manutenção'),
        ('failure', 'Falha'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(TopologyProjectSimple, related_name='devices', on_delete=models.CASCADE)
    
    # Identificação
    name = models.CharField(max_length=255)
    device_type = models.CharField(max_length=20, choices=DEVICE_TYPES)
    
    # Localização simples
    latitude = models.FloatField(help_text="Latitude do dispositivo")
    longitude = models.FloatField(help_text="Longitude do dispositivo")
    altitude = models.FloatField(null=True, blank=True, help_text="Altitude em metros")
    
    # Propriedades técnicas (JSON para flexibilidade)
    properties = models.JSONField(default=dict, help_text="Propriedades técnicas do dispositivo")
    
    # Status operacional
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    
    # Metadados
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'network_devices_simple'
        unique_together = ['project', 'name']
        indexes = [
            models.Index(fields=['project', 'device_type']),
            models.Index(fields=['status']),
            models.Index(fields=['latitude', 'longitude']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.get_device_type_display()})"
    
    def distance_to(self, other_device):
        """Calcula distância em metros para outro dispositivo usando fórmula de Haversine"""
        R = 6371000  # Raio da Terra em metros
        
        lat1, lon1 = math.radians(self.latitude), math.radians(self.longitude)
        lat2, lon2 = math.radians(other_device.latitude), math.radians(other_device.longitude)
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        
        return R * c
    
    def get_location_dict(self):
        """Retorna localização como dicionário"""
        return {
            'latitude': self.latitude,
            'longitude': self.longitude,
            'altitude': self.altitude
        }


class NetworkConnectionSimple(models.Model):
    """Conexão entre dispositivos com caminho simples"""
    
    CONNECTION_TYPES = [
        ('fiber', 'Fibra Óptica'),
        ('wireless', 'Wireless'),
        ('ethernet', 'Ethernet'),
        ('satellite', 'Satélite'),
        ('microwave', 'Microondas'),
        ('logical', 'Lógica'),
    ]
    
    CALCULATION_METHODS = [
        ('manual', 'Manual'),
        ('straight_line', 'Linha Reta'),
        ('custom_algorithm', 'Algoritmo Personalizado'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(TopologyProjectSimple, related_name='connections', on_delete=models.CASCADE)
    
    # Dispositivos conectados
    source_device = models.ForeignKey(NetworkDeviceSimple, related_name='outbound_connections', on_delete=models.CASCADE)
    target_device = models.ForeignKey(NetworkDeviceSimple, related_name='inbound_connections', on_delete=models.CASCADE)
    
    # Tipo e propriedades da conexão
    connection_type = models.CharField(max_length=20, choices=CONNECTION_TYPES)
    properties = models.JSONField(default=dict, help_text="Propriedades técnicas da conexão")
    
    # Caminho como array de coordenadas [lat, lng]
    path_coordinates = models.JSONField(default=list, help_text="Array de coordenadas do caminho")
    
    # Informações de cálculo
    is_calculated = models.BooleanField(default=False, help_text="Se o caminho foi calculado automaticamente")
    calculation_method = models.CharField(max_length=20, choices=CALCULATION_METHODS, default='manual')
    calculation_metadata = models.JSONField(default=dict, help_text="Metadados do cálculo do caminho")
    
    # Estilo visual
    style_properties = models.JSONField(default=dict, help_text="Propriedades de estilo visual")
    
    # Metadados
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'network_connections_simple'
        unique_together = ['source_device', 'target_device']
        indexes = [
            models.Index(fields=['project', 'connection_type']),
            models.Index(fields=['is_calculated']),
        ]
    
    def __str__(self):
        return f"{self.source_device} -> {self.target_device}"
    
    @property
    def length_meters(self):
        """Calcula comprimento em metros"""
        if self.path_coordinates:
            # Calcular distância total do caminho
            total_distance = 0
            for i in range(len(self.path_coordinates) - 1):
                coord1 = self.path_coordinates[i]
                coord2 = self.path_coordinates[i + 1]
                
                # Criar objetos temporários para cálculo
                temp_device1 = type('TempDevice', (), {'latitude': coord1[0], 'longitude': coord1[1]})()
                temp_device2 = type('TempDevice', (), {'latitude': coord2[0], 'longitude': coord2[1]})()
                
                # Usar método de distância do dispositivo
                temp_source = NetworkDeviceSimple(latitude=coord1[0], longitude=coord1[1])
                temp_target = NetworkDeviceSimple(latitude=coord2[0], longitude=coord2[1])
                total_distance += temp_source.distance_to(temp_target)
            
            return total_distance
        else:
            # Linha reta entre dispositivos
            return self.source_device.distance_to(self.target_device)
    
    @property
    def length_kilometers(self):
        """Comprimento em quilômetros"""
        return self.length_meters / 1000
    
    def get_path_coordinates(self):
        """Retorna coordenadas do caminho"""
        return self.path_coordinates
    
    def set_path_from_coordinates(self, coordinates):
        """Define caminho a partir de coordenadas"""
        self.path_coordinates = coordinates
        self.is_calculated = True
        self.save()
    
    def create_straight_line_path(self):
        """Cria caminho em linha reta entre dispositivos"""
        coordinates = [
            [self.source_device.latitude, self.source_device.longitude],
            [self.target_device.latitude, self.target_device.longitude]
        ]
        self.set_path_from_coordinates(coordinates)
        self.calculation_method = 'straight_line'
        self.save()
    
    def export_to_geojson(self):
        """Exporta conexão para GeoJSON"""
        return {
            'type': 'Feature',
            'geometry': {
                'type': 'LineString',
                'coordinates': [[coord[1], coord[0]] for coord in self.path_coordinates]  # GeoJSON usa [lng, lat]
            },
            'properties': {
                'id': str(self.id),
                'connection_type': self.connection_type,
                'length_meters': self.length_meters,
                'style': self.style_properties
            }
        }


class TopologySnapshotSimple(models.Model):
    """Snapshot/versão de uma topologia para histórico"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(TopologyProjectSimple, related_name='snapshots', on_delete=models.CASCADE)
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    
    # Dados completos da topologia em formato JSON
    topology_data = models.JSONField(help_text="Dados completos da topologia em JSON")
    
    # Metadados
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=255, blank=True, null=True)
    
    class Meta:
        db_table = 'topology_snapshots_simple'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.project.name} - {self.name} ({self.created_at})"
