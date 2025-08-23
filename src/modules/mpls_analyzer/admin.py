from django.contrib import admin
from .models import (
    Equipment, MplsConfiguration, VpwsGroup, Vpn, 
    LdpNeighbor, CustomerService, BackupProcessLog
)


@admin.register(Equipment)
class EquipmentAdmin(admin.ModelAdmin):
    list_display = ['name', 'ip_address', 'location', 'equipment_type', 'status', 'last_backup']
    list_filter = ['equipment_type', 'status', 'location']
    search_fields = ['name', 'ip_address', 'location']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(MplsConfiguration)
class MplsConfigurationAdmin(admin.ModelAdmin):
    list_display = ['equipment', 'backup_date', 'processed_at']
    list_filter = ['backup_date', 'processed_at']
    search_fields = ['equipment__name']
    readonly_fields = ['processed_at']


@admin.register(VpwsGroup)
class VpwsGroupAdmin(admin.ModelAdmin):
    list_display = ['mpls_config', 'group_name']
    search_fields = ['group_name', 'mpls_config__equipment__name']


@admin.register(Vpn)
class VpnAdmin(admin.ModelAdmin):
    list_display = ['vpws_group', 'vpn_id', 'neighbor_ip', 'pw_type', 'pw_id']
    list_filter = ['pw_type']
    search_fields = ['neighbor_ip', 'vpws_group__group_name']


@admin.register(LdpNeighbor)
class LdpNeighborAdmin(admin.ModelAdmin):
    list_display = ['mpls_config', 'neighbor_ip', 'targeted']
    list_filter = ['targeted']
    search_fields = ['neighbor_ip', 'mpls_config__equipment__name']


@admin.register(CustomerService)
class CustomerServiceAdmin(admin.ModelAdmin):
    list_display = ['name', 'service_type', 'vpn', 'bandwidth', 'created_at']
    list_filter = ['service_type', 'created_at']
    search_fields = ['name', 'vpn__neighbor_ip']


@admin.register(BackupProcessLog)
class BackupProcessLogAdmin(admin.ModelAdmin):
    list_display = ['started_at', 'finished_at', 'status', 'processed_files', 'total_files', 'user']
    list_filter = ['status', 'started_at']
    search_fields = ['user__username']
    readonly_fields = ['started_at', 'finished_at', 'processed_at']
    
    def processed_at(self, obj):
        return obj.finished_at
    processed_at.short_description = 'Finalizado em'
