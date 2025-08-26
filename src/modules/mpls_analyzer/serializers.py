"""
Serializers para documentação da API do MPLS Analyzer
"""
from rest_framework import serializers


class EquipmentInfoSerializer(serializers.Serializer):
    """Informações do equipamento"""
    id = serializers.IntegerField()
    name = serializers.CharField()
    ip_address = serializers.IPAddressField()
    location = serializers.CharField()
    equipment_type = serializers.CharField()
    status = serializers.CharField()
    last_backup = serializers.DateTimeField(allow_null=True)


class BackupInfoSerializer(serializers.Serializer):
    """Informações do backup JSON"""
    backup_date = serializers.DateTimeField()
    file_name = serializers.CharField()
    file_size = serializers.IntegerField()
    processed_at = serializers.DateTimeField()
    total_interfaces = serializers.IntegerField()
    total_lags = serializers.IntegerField()
    total_vpns = serializers.IntegerField()


class FiltersAppliedSerializer(serializers.Serializer):
    """Filtros aplicados na consulta"""
    sections = serializers.ListField(child=serializers.CharField(), allow_null=True)
    paths = serializers.ListField(child=serializers.CharField(), allow_null=True)


class EquipmentJsonBackupResponseSerializer(serializers.Serializer):
    """Resposta do endpoint de JSON backup do equipamento"""
    equipment = EquipmentInfoSerializer()
    backup_info = BackupInfoSerializer()
    available_sections = serializers.ListField(child=serializers.CharField())
    filters_applied = FiltersAppliedSerializer(required=False)
    json_data = serializers.JSONField(required=False)


class SearchResultSerializer(serializers.Serializer):
    """Resultado individual da busca"""
    type = serializers.CharField()
    equipment_name = serializers.CharField()
    equipment_id = serializers.IntegerField()
    loopback_ip = serializers.CharField()
    location = serializers.CharField()
    last_backup = serializers.DateTimeField(allow_null=True)
    highlights = serializers.ListField(child=serializers.CharField())
    vpn_id = serializers.IntegerField()
    neighbor_ip = serializers.CharField()
    neighbor_hostname = serializers.CharField()
    access_interface = serializers.CharField()
    encapsulation = serializers.CharField()
    description = serializers.CharField()
    group_name = serializers.CharField()
    customers = serializers.ListField(child=serializers.CharField())
    total_vpns = serializers.IntegerField()


class SearchResponseSerializer(serializers.Serializer):
    """Resposta da busca MPLS"""
    results = SearchResultSerializer(many=True)
    total_results = serializers.IntegerField()
    query_time_ms = serializers.FloatField()


class VPNServiceSerializer(serializers.Serializer):
    """Serviço de cliente em uma VPN"""
    name = serializers.CharField()
    type = serializers.CharField()
    bandwidth = serializers.CharField()


class VPNSideSerializer(serializers.Serializer):
    """Uma ponta da VPN (side A ou B)"""
    equipment = EquipmentInfoSerializer()
    interface = serializers.CharField()
    encapsulation_details = serializers.JSONField(required=False)
    neighbor = serializers.JSONField(required=False)


class VPNReportSerializer(serializers.Serializer):
    """Relatório de uma VPN"""
    vpn_id = serializers.IntegerField()
    customers = serializers.ListField(child=serializers.CharField())
    encapsulation = serializers.CharField()
    encapsulation_type = serializers.CharField()
    side_a = VPNSideSerializer(allow_null=True)
    side_b = VPNSideSerializer(allow_null=True)
    services = VPNServiceSerializer(many=True)


class CustomerReportResponseSerializer(serializers.Serializer):
    """Resposta do relatório de cliente"""
    results = VPNReportSerializer(many=True)
    customer = serializers.CharField()
    total_vpns = serializers.IntegerField()
    query_time_ms = serializers.FloatField()


class EquipmentVPNsResponseSerializer(serializers.Serializer):
    """Resposta das VPNs por equipamento"""
    equipment = EquipmentInfoSerializer()
    vpns = VPNReportSerializer(many=True)
    total_vpns = serializers.IntegerField()


class ImportStatsSerializer(serializers.Serializer):
    """Estatísticas de importação de JSONs"""
    log_id = serializers.IntegerField()
    processed_files = serializers.IntegerField()
    successful_imports = serializers.IntegerField()
    failed_imports = serializers.IntegerField()
    errors = serializers.ListField(child=serializers.CharField())
    started_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField(allow_null=True)


class CollectAndImportRequestSerializer(serializers.Serializer):
    """Request para coletar e importar JSONs"""
    username = serializers.CharField(help_text="Login SSH para equipamentos")
    password = serializers.CharField(help_text="Senha SSH para equipamentos", write_only=True)
    remove_on_success = serializers.BooleanField(default=False, help_text="Remover JSON após importar")


class ImportJsonsRequestSerializer(serializers.Serializer):
    """Request para importar JSONs existentes"""
    path = serializers.CharField(required=False, help_text="Diretório com arquivos JSON")
    remove_on_success = serializers.BooleanField(default=False, help_text="Remover JSON após importar")


class ErrorResponseSerializer(serializers.Serializer):
    """Resposta de erro padrão"""
    error = serializers.CharField()
    message = serializers.CharField()
    examples = serializers.JSONField(required=False)