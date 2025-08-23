#!/usr/bin/env python
"""
Script para migrar dados MPLS do sistema antigo para o CoreWise
Executa: python migrate_mpls_data.py
"""

import os
import sys
import sqlite3
from datetime import datetime

# Configurar Django
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'corewiseengnir.settings')

import django
django.setup()

from modules.mpls_analyzer.models import Equipment, MplsConfiguration, CustomerService, Vpn, VpwsGroup
from django.contrib.auth.models import User


def migrate_mpls_data():
    """Migra dados do banco antigo para o novo"""
    
    old_db_path = '/home/tayron/Documentos/github/CoreWise/SYSTEMA-PARA-INTEGRAR/db.sqlite3'
    
    if not os.path.exists(old_db_path):
        print(f"❌ Banco antigo não encontrado: {old_db_path}")
        return
    
    # Conectar ao banco antigo
    old_conn = sqlite3.connect(old_db_path)
    old_conn.row_factory = sqlite3.Row  # Para acessar por nome da coluna
    old_cursor = old_conn.cursor()
    
    print("🔄 Iniciando migração de dados MPLS...")
    
    try:
        # Migrar Equipamentos
        print("📋 Migrando equipamentos...")
        old_cursor.execute("SELECT * FROM mpls_analyzer_equipment")
        equipments = old_cursor.fetchall()
        
        equipment_map = {}  # Para mapear IDs antigos -> novos
        
        for old_eq in equipments:
            new_eq, created = Equipment.objects.get_or_create(
                name=old_eq['name'],
                defaults={
                    'location': old_eq['location'] or '',
                    'ip_address': old_eq['ip_address'] or '',
                    'backup_enabled': bool(old_eq['backup_enabled']),
                    'created_at': old_eq['created_at']
                }
            )
            equipment_map[old_eq['id']] = new_eq.id
            
            if created:
                print(f"  ✅ {new_eq.name} em {new_eq.location}")
        
        print(f"📋 {len(equipments)} equipamentos migrados")
        
        # Migrar Grupos VPWS
        print("🔗 Migrando grupos VPWS...")
        old_cursor.execute("SELECT * FROM mpls_analyzer_vpwsgroup")
        vpws_groups = old_cursor.fetchall()
        
        vpws_group_map = {}
        
        for old_group in vpws_groups:
            equipment_id = equipment_map.get(old_group['equipment_id'])
            if equipment_id:
                new_group, created = VpwsGroup.objects.get_or_create(
                    name=old_group['name'],
                    equipment_id=equipment_id,
                    defaults={
                        'description': old_group['description'] or '',
                        'created_at': old_group['created_at']
                    }
                )
                vpws_group_map[old_group['id']] = new_group.id
                
                if created:
                    print(f"  ✅ {new_group.name}")
        
        print(f"🔗 {len(vpws_groups)} grupos VPWS migrados")
        
        # Migrar VPNs
        print("🌐 Migrando VPNs...")
        old_cursor.execute("SELECT * FROM mpls_analyzer_vpn")
        vpns = old_cursor.fetchall()
        
        vpn_map = {}
        
        for old_vpn in vpns:
            vpws_group_id = vpws_group_map.get(old_vpn['vpws_group_id'])
            if vpws_group_id:
                new_vpn, created = Vpn.objects.get_or_create(
                    vpn_id=old_vpn['vpn_id'],
                    vpws_group_id=vpws_group_id,
                    defaults={
                        'name': old_vpn['name'] or f"VPN-{old_vpn['vpn_id']}",
                        'description': old_vpn['description'] or '',
                        'created_at': old_vpn['created_at']
                    }
                )
                vpn_map[old_vpn['id']] = new_vpn.id
                
                if created:
                    print(f"  ✅ VPN {new_vpn.vpn_id}: {new_vpn.name}")
        
        print(f"🌐 {len(vpns)} VPNs migradas")
        
        # Migrar Serviços de Cliente
        print("👥 Migrando serviços de cliente...")
        old_cursor.execute("SELECT * FROM mpls_analyzer_customerservice")
        services = old_cursor.fetchall()
        
        for old_service in services:
            vpn_id = vpn_map.get(old_service['vpn_id'])
            if vpn_id:
                new_service, created = CustomerService.objects.get_or_create(
                    name=old_service['name'],
                    vpn_id=vpn_id,
                    service_type=old_service['service_type'],
                    defaults={
                        'bandwidth': old_service['bandwidth'] or '',
                        'created_at': old_service['created_at']
                    }
                )
                
                if created:
                    print(f"  ✅ {new_service.name} ({new_service.service_type})")
        
        print(f"👥 {len(services)} serviços de cliente migrados")
        
        # Migrar Configurações MPLS
        print("⚙️ Migrando configurações...")
        old_cursor.execute("SELECT * FROM mpls_analyzer_mplsconfiguration")
        configs = old_cursor.fetchall()
        
        for old_config in configs:
            equipment_id = equipment_map.get(old_config['equipment_id'])
            if equipment_id:
                new_config, created = MplsConfiguration.objects.get_or_create(
                    equipment_id=equipment_id,
                    backup_date=old_config['backup_date'],
                    defaults={
                        'raw_config': old_config['raw_config'] or '',
                        'config_hash': old_config['config_hash'] or '',
                        'file_path': old_config['file_path'] or '',
                        'file_size': old_config['file_size'] or 0,
                        'created_at': old_config['created_at']
                    }
                )
                
                if created:
                    print(f"  ✅ Config {new_config.equipment.name} ({new_config.backup_date})")
        
        print(f"⚙️ {len(configs)} configurações migradas")
        
        # Verificar migração
        print("\n📊 RESUMO DA MIGRAÇÃO:")
        print(f"  Equipamentos: {Equipment.objects.count()}")
        print(f"  Configurações: {MplsConfiguration.objects.count()}")
        print(f"  Grupos VPWS: {VpwsGroup.objects.count()}")
        print(f"  VPNs: {Vpn.objects.count()}")
        print(f"  Serviços de Cliente: {CustomerService.objects.count()}")
        
        # Testar busca MEGALINK
        megalink_count = CustomerService.objects.filter(name__icontains='MEGALINK').count()
        print(f"  Serviços MEGALINK encontrados: {megalink_count}")
        
        print("\n✅ MIGRAÇÃO CONCLUÍDA COM SUCESSO!")
        
    except Exception as e:
        print(f"❌ Erro durante a migração: {e}")
        raise
    
    finally:
        old_conn.close()

if __name__ == '__main__':
    migrate_mpls_data()