"""
Serviços para exportação e manipulação de dados geoespaciais
"""
import zipfile
import io
from datetime import datetime
from django.http import HttpResponse
from django.template.loader import render_to_string
from .models_geo import TopologyProjectGeo, NetworkDeviceGeo, NetworkConnectionGeo

class TopologyGeoExporter:
    """Exportador de topologias para formatos geoespaciais"""
    
    def __init__(self, project):
        self.project = project
    
    def export_to_kml(self):
        """Exporta projeto completo para KML"""
        devices = self.project.devices.all()
        connections = self.project.connections.all()
        
        kml_content = self._generate_kml_content(devices, connections)
        
        response = HttpResponse(kml_content, content_type='application/vnd.google-earth.kml+xml')
        response['Content-Disposition'] = f'attachment; filename="{self.project.name}.kml"'
        return response
    
    def export_to_kmz(self):
        """Exporta projeto completo para KMZ (KML compactado)"""
        devices = self.project.devices.all()
        connections = self.project.connections.all()
        
        kml_content = self._generate_kml_content(devices, connections)
        
        # Criar arquivo ZIP em memória
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr('doc.kml', kml_content)
            
            # Adicionar ícones personalizados se necessário
            # zip_file.writestr('icons/router.png', self._get_router_icon())
            # zip_file.writestr('icons/switch.png', self._get_switch_icon())
        
        zip_buffer.seek(0)
        
        response = HttpResponse(zip_buffer.read(), content_type='application/vnd.google-earth.kmz')
        response['Content-Disposition'] = f'attachment; filename="{self.project.name}.kmz"'
        return response
    
    def _generate_kml_content(self, devices, connections):
        """Gera conteúdo KML completo"""
        
        kml_template = '''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>{project_name}</name>
    <description>{project_description}</description>
    
    <!-- Estilos para dispositivos -->
    <Style id="router_style">
      <IconStyle>
        <color>ff0000ff</color>
        <scale>1.2</scale>
        <Icon>
          <href>http://maps.google.com/mapfiles/kml/shapes/electronics.png</href>
        </Icon>
      </IconStyle>
      <LabelStyle>
        <scale>0.8</scale>
      </LabelStyle>
    </Style>
    
    <Style id="switch_style">
      <IconStyle>
        <color>ff00ff00</color>
        <scale>1.0</scale>
        <Icon>
          <href>http://maps.google.com/mapfiles/kml/shapes/electronics.png</href>
        </Icon>
      </IconStyle>
    </Style>
    
    <Style id="server_style">
      <IconStyle>
        <color>ffff8800</color>
        <scale>1.1</scale>
        <Icon>
          <href>http://maps.google.com/mapfiles/kml/shapes/computers.png</href>
        </Icon>
      </IconStyle>
    </Style>
    
    <!-- Estilos para conexões -->
    <Style id="fiber_connection">
      <LineStyle>
        <color>ff0000ff</color>
        <width>4</width>
      </LineStyle>
    </Style>
    
    <Style id="wireless_connection">
      <LineStyle>
        <color>ff00ff00</color>
        <width>2</width>
        <gx:labelVisibility>1</gx:labelVisibility>
      </LineStyle>
    </Style>
    
    <Style id="ethernet_connection">
      <LineStyle>
        <color>ffff8800</color>
        <width>3</width>
      </LineStyle>
    </Style>
    
    <!-- Pasta de Dispositivos -->
    <Folder>
      <name>Dispositivos de Rede</name>
      <description>Equipamentos da topologia</description>
      {devices_kml}
    </Folder>
    
    <!-- Pasta de Conexões -->
    <Folder>
      <name>Conexões de Rede</name>
      <description>Caminhos entre dispositivos</description>
      {connections_kml}
    </Folder>
    
  </Document>
</kml>'''
        
        # Gerar KML para dispositivos
        devices_kml = []
        for device in devices:
            if device.location:
                device_kml = f'''
      <Placemark>
        <name>{device.name}</name>
        <description><![CDATA[
          <strong>Tipo:</strong> {device.get_device_type_display()}<br/>
          <strong>Status:</strong> {device.get_status_display()}<br/>
          <strong>Coordenadas:</strong> {device.latitude:.6f}, {device.longitude:.6f}<br/>
          {self._format_device_properties(device.properties)}
        ]]></description>
        <styleUrl>#{device.device_type}_style</styleUrl>
        <Point>
          <coordinates>{device.longitude},{device.latitude},{device.altitude or 0}</coordinates>
        </Point>
      </Placemark>'''
                devices_kml.append(device_kml)
        
        # Gerar KML para conexões
        connections_kml = []
        for connection in connections:
            if connection.path_geometry:
                coords_kml = []
                for coord in connection.path_geometry.coords:
                    coords_kml.append(f"{coord[0]},{coord[1]},0")
                
                connection_kml = f'''
      <Placemark>
        <name>{connection.source_device.name} → {connection.target_device.name}</name>
        <description><![CDATA[
          <strong>Tipo:</strong> {connection.get_connection_type_display()}<br/>
          <strong>Comprimento:</strong> {connection.length_kilometers or 'N/A'} km<br/>
          <strong>Calculado:</strong> {'Sim' if connection.is_calculated else 'Não'}<br/>
          <strong>Método:</strong> {connection.get_calculation_method_display()}<br/>
          {self._format_connection_properties(connection.properties)}
        ]]></description>
        <styleUrl>#{connection.connection_type}_connection</styleUrl>
        <LineString>
          <tessellate>1</tessellate>
          <coordinates>{' '.join(coords_kml)}</coordinates>
        </LineString>
      </Placemark>'''
                connections_kml.append(connection_kml)
        
        return kml_template.format(
            project_name=self.project.name,
            project_description=self.project.description or 'Topologia de rede',
            devices_kml=''.join(devices_kml),
            connections_kml=''.join(connections_kml)
        )
    
    def _format_device_properties(self, properties):
        """Formata propriedades do dispositivo para exibição"""
        if not properties:
            return ''
        
        formatted = []
        for key, value in properties.items():
            if value:
                formatted.append(f"<strong>{key.replace('_', ' ').title()}:</strong> {value}<br/>")
        
        return ''.join(formatted)
    
    def _format_connection_properties(self, properties):
        """Formata propriedades da conexão para exibição"""
        if not properties:
            return ''
        
        formatted = []
        for key, value in properties.items():
            if value:
                if key == 'bandwidth':
                    formatted.append(f"<strong>Largura de Banda:</strong> {value}<br/>")
                elif key == 'latency':
                    formatted.append(f"<strong>Latência:</strong> {value}ms<br/>")
                elif key == 'utilization':
                    formatted.append(f"<strong>Utilização:</strong> {value}%<br/>")
                else:
                    formatted.append(f"<strong>{key.replace('_', ' ').title()}:</strong> {value}<br/>")
        
        return ''.join(formatted)
    
    def export_to_geojson(self):
        """Exporta projeto para GeoJSON"""
        devices = self.project.devices.all()
        connections = self.project.connections.all()
        
        geojson = {
            "type": "FeatureCollection",
            "name": self.project.name,
            "features": []
        }
        
        # Adicionar dispositivos
        for device in devices:
            if device.location:
                feature = {
                    "type": "Feature",
                    "properties": {
                        "id": str(device.id),
                        "name": device.name,
                        "device_type": device.device_type,
                        "status": device.status,
                        **device.properties
                    },
                    "geometry": {
                        "type": "Point",
                        "coordinates": [device.longitude, device.latitude, device.altitude or 0]
                    }
                }
                geojson["features"].append(feature)
        
        # Adicionar conexões
        for connection in connections:
            if connection.path_geometry:
                feature = {
                    "type": "Feature",
                    "properties": {
                        "id": str(connection.id),
                        "source_device": connection.source_device.name,
                        "target_device": connection.target_device.name,
                        "connection_type": connection.connection_type,
                        "length_km": connection.length_kilometers,
                        "is_calculated": connection.is_calculated,
                        **connection.properties
                    },
                    "geometry": {
                        "type": "LineString",
                        "coordinates": [[coord[0], coord[1], 0] for coord in connection.path_geometry.coords]
                    }
                }
                geojson["features"].append(feature)
        
        import json
        response = HttpResponse(json.dumps(geojson, indent=2), content_type='application/geo+json')
        response['Content-Disposition'] = f'attachment; filename="{self.project.name}.geojson"'
        return response


class PathCalculator:
    """Calculadora de caminhos usando diferentes métodos"""
    
    @staticmethod
    def calculate_road_path(source_device, target_device, routing_service='osrm'):
        """Calcula caminho usando APIs de roteamento"""
        from .services.routingService import calculateRoadRoute
        
        source_coords = [source_device.latitude, source_device.longitude]
        target_coords = [target_device.latitude, target_device.longitude]
        
        try:
            # Usar o serviço de roteamento existente
            path_coords = calculateRoadRoute(source_coords, target_coords)
            return path_coords
        except Exception as e:
            print(f"Erro no cálculo de rota: {e}")
            # Fallback para linha reta
            return [source_coords, target_coords]
    
    @staticmethod
    def optimize_path_points(coordinates, max_points=100):
        """Otimiza pontos do caminho para reduzir complexidade"""
        if len(coordinates) <= max_points:
            return coordinates
        
        # Algoritmo simples de simplificação
        step = len(coordinates) // max_points
        optimized = []
        
        # Sempre incluir primeiro e último ponto
        optimized.append(coordinates[0])
        
        for i in range(step, len(coordinates) - step, step):
            optimized.append(coordinates[i])
        
        optimized.append(coordinates[-1])
        
        return optimized


class TopologyAnalyzer:
    """Analisador de topologias para métricas e insights"""
    
    def __init__(self, project):
        self.project = project
    
    def calculate_network_metrics(self):
        """Calcula métricas da rede"""
        devices = self.project.devices.all()
        connections = self.project.connections.all()
        
        metrics = {
            'total_devices': devices.count(),
            'total_connections': connections.count(),
            'device_types': {},
            'connection_types': {},
            'total_length_km': 0,
            'calculated_paths': 0,
            'average_connection_length': 0,
        }
        
        # Contar tipos de dispositivos
        for device in devices:
            device_type = device.device_type
            metrics['device_types'][device_type] = metrics['device_types'].get(device_type, 0) + 1
        
        # Analisar conexões
        total_length = 0
        calculated_count = 0
        
        for connection in connections:
            conn_type = connection.connection_type
            metrics['connection_types'][conn_type] = metrics['connection_types'].get(conn_type, 0) + 1
            
            if connection.length_kilometers:
                total_length += connection.length_kilometers
            
            if connection.is_calculated:
                calculated_count += 1
        
        metrics['total_length_km'] = round(total_length, 2)
        metrics['calculated_paths'] = calculated_count
        
        if connections.count() > 0:
            metrics['average_connection_length'] = round(total_length / connections.count(), 2)
        
        return metrics
    
    def find_isolated_devices(self):
        """Encontra dispositivos sem conexões"""
        devices_with_connections = set()
        
        for connection in self.project.connections.all():
            devices_with_connections.add(connection.source_device.id)
            devices_with_connections.add(connection.target_device.id)
        
        isolated = []
        for device in self.project.devices.all():
            if device.id not in devices_with_connections:
                isolated.append(device)
        
        return isolated
    
    def calculate_network_density(self):
        """Calcula densidade da rede"""
        device_count = self.project.devices.count()
        connection_count = self.project.connections.count()
        
        if device_count < 2:
            return 0
        
        max_possible_connections = device_count * (device_count - 1) / 2
        density = (connection_count / max_possible_connections) * 100
        
        return round(density, 2)