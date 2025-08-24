#!/usr/bin/env python3
"""
Script para importar todos os 103 arquivos JSON dos equipamentos Datacom
"""
import os
import sys
import django
from pathlib import Path

# Setup Django (ensure project root is on sys.path)
# This script lives at src/modules/mpls_analyzer/import_all_jsons.py
# We need to add src/ to sys.path so 'config.settings' can be imported.
SRC_DIR = Path(__file__).resolve().parents[2]
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from modules.mpls_analyzer.models import EquipmentJsonBackup
from modules.mpls_analyzer.services.import_jsons import import_jsons_from_dir

def main():
    """Importa todos os arquivos JSON"""
    script_dir = Path(__file__).parent
    preferred = script_dir / 'update'
    legacy = script_dir / 'backupjson-equipamentos'
    json_dir = preferred if preferred.exists() else legacy
    
    if not json_dir.exists():
        print(f"❌ Diretório não encontrado: {json_dir}")
        sys.exit(1)
    
    stats = import_jsons_from_dir(json_dir, verbose=True)

    print("\n" + "=" * 80)
    print("🎉 IMPORTAÇÃO CONCLUÍDA!")
    print("=" * 80)
    print(f"   • Total de arquivos: {stats.total}")
    print(f"   • ✅ Sucessos: {stats.success}")
    print(f"   • ⏭️  Pulados: {stats.skipped}")
    print(f"   • ❌ Erros: {stats.errors}")

if __name__ == '__main__':
    main()
