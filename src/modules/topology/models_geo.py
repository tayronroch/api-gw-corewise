"""
Modelos GeoDjango para topologia de rede com suporte espacial completo
Requer PostgreSQL com extensão PostGIS
TEMPORARIAMENTE DESABILITADO - Usando modelos simplificados em models_simple.py
"""
# from django.contrib.gis.db import models
# from django.contrib.gis.geos import Point, LineString
# import uuid
# import json

# class TopologyProjectGeo(models.Model):
#     """Projeto de topologia com informações geoespaciais"""
#     
#     ZOOM_CHOICES = [(i, str(i)) for i in range(1, 19)]
#     
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     name = models.CharField(max_length=255)
#     description = models.TextField(blank=True, null=True)
#     
#     # Geometrias espaciais
#     bounds = models.PolygonField(srid=4326, null=True, blank=True, help_text="Limites geográficos do projeto")
#     center_point = models.PointField(srid=4326, help_text="Ponto central do projeto")
#     zoom_level = models.IntegerField(choices=ZOOM_CHOICES, default=10)
#     
#     # Metadados
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)
#     
#     # Índices espaciais automáticos
#     class Meta:
#         db_table = 'topology_projects_geo'
#         indexes = [
#             models.Index(fields=['name']),
#             models.Index(fields=['created_at']),
#         ]
#     
#     def __str__(self):
#         return self.name
#     
#     def get_bounds_geojson(self):
#         """Retorna os limites como GeoJSON"""
#         if self.bounds:
#             return self.bounds.geojson
#         return None
#     
#     def calculate_bounds_from_devices(self):
#         """Calcula limites automaticamente baseado nos dispositivos"""
#         devices = self.devices.all()
#         if devices.exists():
#             # Usar PostGIS para calcular envelope
#             from django.contrib.gis.db.models import Extent
#             extent = devices.aggregate(extent=Extent('location'))['extent']
#             if extent:
#                 # Criar polígono dos limites com margem
#                 from django.contrib.gis.geos import Polygon
#                 margin = 0.01  # ~1km de margem
#                 bounds = Polygon.from_bbox((
#                     extent[0] - margin, extent[1] - margin,
#                     extent[2] + margin, extent[3] + margin
#                 ))
#                 self.bounds = bounds
#                 self.save()

# TODO: Comentar o resto do arquivo também


class NetworkDeviceGeo(models.Model):
    """Dispositivo de rede com localização geoespacial"""
    
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
    project = models.ForeignKey(TopologyProjectGeo, related_name='devices', on_delete=models.CASCADE)
    
    # Identificação
    name = models.CharField(max_length=255)
    device_type = models.CharField(max_length=20, choices=DEVICE_TYPES)
    
    # Localização espacial
    location = models.PointField(srid=4326, help_text="Localização exata do dispositivo")
    altitude = models.FloatField(null=True, blank=True, help_text="Altitude em metros")
    
    # Propriedades técnicas (JSONB para flexibilidade)
    properties = models.JSONField(default=dict, help_text="Propriedades técnicas do dispositivo")
    
    # Status operacional
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    
    # Metadados
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'network_devices_geo'
        unique_together = ['project', 'name']
        indexes = [
            models.Index(fields=['device_type']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.get_device_type_display()})"
    
    @property
    def latitude(self):
        return self.location.y if self.location else None
    
    @property
    def longitude(self):
        return self.location.x if self.location else None
    
    def get_location_geojson(self):
        """Retorna localização como GeoJSON"""
        return self.location.geojson if self.location else None
    
    def distance_to(self, other_device):
        """Calcula distância para outro dispositivo usando PostGIS"""
        if self.location and other_device.location:
            return self.location.distance(other_device.location) * 111000  # Conversão para metros aproximada
        return None


class NetworkConnectionGeo(models.Model):
    """Conexão entre dispositivos com geometria de caminho"""
    
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
        ('routing_api', 'API de Roteamento'),
        ('straight_line', 'Linha Reta'),
        ('custom_algorithm', 'Algoritmo Personalizado'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(TopologyProjectGeo, related_name='connections', on_delete=models.CASCADE)
    
    # Dispositivos conectados
    source_device = models.ForeignKey(NetworkDeviceGeo, related_name='outbound_connections', on_delete=models.CASCADE)
    target_device = models.ForeignKey(NetworkDeviceGeo, related_name='inbound_connections', on_delete=models.CASCADE)
    
    # Geometria do caminho (LINESTRING com múltiplos pontos)
    path_geometry = models.LineStringField(srid=4326, help_text="Caminho geométrico da conexão")
    
    # Tipo e propriedades da conexão
    connection_type = models.CharField(max_length=20, choices=CONNECTION_TYPES)
    properties = models.JSONField(default=dict, help_text="Propriedades técnicas da conexão")
    
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
        db_table = 'network_connections_geo'
        unique_together = ['source_device', 'target_device']
        indexes = [
            models.Index(fields=['connection_type']),
            models.Index(fields=['is_calculated']),
        ]
    
    def __str__(self):
        return f"{self.source_device.name} → {self.target_device.name}"
    
    @property
    def length_meters(self):
        """Calcula comprimento real do caminho em metros usando PostGIS"""
        if self.path_geometry:
            # PostGIS ST_Length em graus, convertido para metros
            from django.contrib.gis.db.models import functions
            return self.path_geometry.length * 111000  # Aproximação
        return None
    
    @property
    def length_kilometers(self):
        """Comprimento em quilômetros"""
        length = self.length_meters
        return round(length / 1000, 2) if length else None
    
    def get_path_geojson(self):
        """Retorna caminho como GeoJSON"""
        return self.path_geometry.geojson if self.path_geometry else None
    
    def get_path_coordinates(self):
        """Retorna coordenadas do caminho como lista de [lat, lng]"""
        if self.path_geometry:
            return [[coord[1], coord[0]] for coord in self.path_geometry.coords]
        return []
    
    def set_path_from_coordinates(self, coordinates):
        """Define caminho a partir de lista de [lat, lng]"""
        if coordinates and len(coordinates) >= 2:
            # Converter [lat, lng] para [lng, lat] (formato PostGIS)
            coords = [(coord[1], coord[0]) for coord in coordinates]
            self.path_geometry = LineString(coords, srid=4326)
    
    def create_straight_line_path(self):
        """Cria caminho em linha reta entre os dispositivos"""
        if self.source_device.location and self.target_device.location:
            coords = [
                (self.source_device.location.x, self.source_device.location.y),
                (self.target_device.location.x, self.target_device.location.y)
            ]
            self.path_geometry = LineString(coords, srid=4326)
            self.calculation_method = 'straight_line'
            self.is_calculated = True
    
    def export_to_kml(self):
        """Exporta conexão para formato KML"""
        if not self.path_geometry:
            return None
        
        kml_template = """
        <Placemark>
            <name>{name}</name>
            <description>
                <![CDATA[
                    <strong>Tipo:</strong> {connection_type}<br/>
                    <strong>Comprimento:</strong> {length} km<br/>
                    <strong>Origem:</strong> {source}<br/>
                    <strong>Destino:</strong> {target}
                ]]>
            </description>
            <LineString>
                <coordinates>{coordinates}</coordinates>
            </LineString>
        </Placemark>
        """
        
        # Converter coordenadas para formato KML (lng,lat,alt)
        coords_kml = []
        for coord in self.path_geometry.coords:
            coords_kml.append(f"{coord[0]},{coord[1]},0")
        
        return kml_template.format(
            name=str(self),
            connection_type=self.get_connection_type_display(),
            length=self.length_kilometers or 'N/A',
            source=self.source_device.name,
            target=self.target_device.name,
            coordinates=' '.join(coords_kml)
        )


class TopologySnapshot(models.Model):
    """Snapshot/versão de uma topologia para histórico"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(TopologyProjectGeo, related_name='snapshots', on_delete=models.CASCADE)
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    
    # Dados completos da topologia em formato GeoJSON
    topology_data = models.JSONField(help_text="Dados completos da topologia em GeoJSON")
    
    # Metadados
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=255, blank=True, null=True)
    
    class Meta:
        db_table = 'topology_snapshots'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.project.name} - {self.name}"