#!/usr/bin/env python3
"""
Script para atualizar membros LAG baseado nos arquivos JSON dos equipamentos Datacom
"""
import os
import sys
import json
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from modules.mpls_analyzer.models import Equipment, Interface, LagMember, MplsConfiguration

def process_equipment_json(json_file_path):
    """Processa um arquivo JSON de equipamento e extrai dados de LAG"""
    with open(json_file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Extrair nome do equipamento do nome do arquivo
    equipment_name = os.path.basename(json_file_path).replace('.json', '')
    print(f"\n=== Processando {equipment_name} ===")
    
    # Buscar equipamento no banco
    try:
        equipment = Equipment.objects.get(name=equipment_name)
    except Equipment.DoesNotExist:
        print(f"⚠️  Equipamento {equipment_name} não encontrado no banco")
        return
    
    # Buscar configuração MPLS mais recente deste equipamento
    mpls_config = MplsConfiguration.objects.filter(equipment=equipment).first()
    if not mpls_config:
        print(f"⚠️  Nenhuma configuração MPLS encontrada para {equipment_name}")
        return
    
    # Extrair dados de LAGs do JSON
    lag_data = []
    try:
        link_agg = data.get('data', {}).get('lacp:link-aggregation', {})
        lags = link_agg.get('interface', {}).get('lag', [])
        
        for lag in lags:
            lag_id = lag.get('lag-id')
            config = lag.get('interface-lag-config', {})
            description = config.get('description', '')
            members = []
            
            # Extrair membros
            for member in lag.get('interface-config', []):
                interface_name = member.get('interface-name')
                if interface_name:
                    members.append(interface_name)
            
            if lag_id and members:
                lag_data.append({
                    'lag_id': lag_id,
                    'description': description,
                    'members': members
                })
        
    except Exception as e:
        print(f"❌ Erro ao processar LAGs do JSON: {e}")
        return
    
    print(f"📊 Encontradas {len(lag_data)} LAGs no JSON")
    
    # Processar cada LAG
    updated_count = 0
    created_count = 0
    
    for lag_info in lag_data:
        lag_name = f"lag-{lag_info['lag_id']}"
        description = lag_info['description']
        members = lag_info['members']
        
        print(f"\n🔗 Processando {lag_name}")
        print(f"   Descrição: {description}")
        print(f"   Membros: {', '.join(members)}")
        
        # Buscar ou criar interface LAG
        interface, created = Interface.objects.get_or_create(
            mpls_config=mpls_config,
            name=lag_name,
            defaults={
                'description': description,
                'interface_type': 'lag',
                'speed': '',  # Será inferido baseado nos membros
                'is_customer_interface': True
            }
        )
        
        if created:
            created_count += 1
            print(f"   ✅ Interface LAG criada: {lag_name}")
        else:
            # Atualizar descrição se mudou
            if interface.description != description:
                interface.description = description
                interface.save()
                print(f"   📝 Descrição atualizada")
        
        # Limpar membros existentes
        existing_members = LagMember.objects.filter(lag_interface=interface)
        existing_members.delete()
        
        # Adicionar novos membros
        for member_name in members:
            LagMember.objects.create(
                lag_interface=interface,
                member_interface_name=member_name
            )
        
        updated_count += 1
        print(f"   ✅ {len(members)} membros atualizados")
    
    print(f"\n📈 Resumo para {equipment_name}:")
    print(f"   • LAGs criadas: {created_count}")
    print(f"   • LAGs atualizadas: {updated_count}")
    print(f"   • Total de LAGs processadas: {len(lag_data)}")

def main():
    """Processa todos os arquivos JSON na pasta backupjson-equipamentos"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    json_dir = os.path.join(script_dir, 'backupjson-equipamentos')
    
    if not os.path.exists(json_dir):
        print(f"❌ Diretório não encontrado: {json_dir}")
        sys.exit(1)
    
    # Listar arquivos JSON
    json_files = [f for f in os.listdir(json_dir) if f.endswith('.json')]
    print(f"🔍 Encontrados {len(json_files)} arquivos JSON")
    
    if not json_files:
        print("❌ Nenhum arquivo JSON encontrado")
        sys.exit(1)
    
    # Processar apenas alguns equipamentos para teste
    test_files = [
        'PI-TERESINA-PICARRA-PE02.json',
        'PI-TERESINA-PICARRA-PE03.json',
        'PI-TERESINA-PLANALTO-PE01.json'
    ]
    
    print("🧪 Modo teste: processando apenas alguns equipamentos...")
    for filename in test_files:
        if filename in json_files:
            json_path = os.path.join(json_dir, filename)
            try:
                process_equipment_json(json_path)
            except Exception as e:
                print(f"❌ Erro ao processar {filename}: {e}")
                continue
    
    print("\n🎉 Processamento concluído!")
    
    # Estatísticas finais
    total_lags = Interface.objects.filter(interface_type='lag').count()
    total_members = LagMember.objects.count()
    print(f"\n📊 Estatísticas finais:")
    print(f"   • Total de LAGs no banco: {total_lags}")
    print(f"   • Total de membros LAG: {total_members}")

if __name__ == '__main__':
    main()