from django.core.management.base import BaseCommand
from django.utils import timezone
from modules.mpls_analyzer.models import Equipment, MplsConfiguration
from modules.mpls_analyzer.network_scanner import scan_network_command
from modules.mpls_analyzer.backup_manager import backup_all_devices_command, get_backup_status_command
import os
import subprocess
import sys
from pathlib import Path


class Command(BaseCommand):
    help = 'Processa backups usando os scripts do sistema original'

    def add_arguments(self, parser):
        parser.add_argument(
            '--backup-dir',
            type=str,
            help='Diretório de backup para processar'
        )
        parser.add_argument(
            '--scan-network',
            action='store_true',
            help='Executa scan da rede antes do backup'
        )
        parser.add_argument(
            '--username',
            type=str,
            help='Usuário para acesso aos equipamentos'
        )
        parser.add_argument(
            '--password',
            type=str,
            help='Senha para acesso aos equipamentos'
        )

    def handle(self, *args, **options):
        self.stdout.write('🚀 Iniciando processamento de backups com scripts originais...')
        
        # Define diretório base
        base_dir = Path(__file__).resolve().parent.parent.parent.parent
        scripts_dir = base_dir / 'modules' / 'mpls_analyzer' / 'scripts'
        
        if not scripts_dir.exists():
            self.stdout.write(self.style.ERROR(f'❌ Diretório de scripts não encontrado: {scripts_dir}'))
            return
        
        # Verifica scripts disponíveis
        scan_script = scripts_dir / 'scan-network.py'
        backup_script = scripts_dir / 'easy-bkp-optimized.py'
        
        if not scan_script.exists():
            self.stdout.write(self.style.ERROR(f'❌ Script de scan não encontrado: {scan_script}'))
            return
        
        if not backup_script.exists():
            self.stdout.write(self.style.ERROR(f'❌ Script de backup não encontrado: {backup_script}'))
            return
        
        # Executa scan da rede se solicitado
        if options['scan_network']:
            self.stdout.write('📡 Executando scan da rede...')
            try:
                # Usa o módulo integrado
                hosts_info = scan_network_command(
                    username=options['username'],
                    password=options['password']
                )
                
                if hosts_info:
                    self.stdout.write(self.style.SUCCESS(f'✅ Scan da rede concluído! {len(hosts_info)} hosts encontrados'))
                else:
                    self.stdout.write(self.style.WARNING('⚠️ Nenhum host encontrado no scan'))
                    
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'❌ Erro no scan da rede: {e}'))
                import traceback
                traceback.print_exc()
        
        # Executa backup dos equipamentos
        self.stdout.write('💾 Executando backup dos equipamentos...')
        try:
            # Usa o módulo integrado
            success_count, total_count = backup_all_devices_command(
                username=options['username'],
                password=options['password']
            )
            
            if success_count > 0:
                self.stdout.write(self.style.SUCCESS(f'✅ Backup dos equipamentos concluído! {success_count}/{total_count} sucessos'))
            else:
                self.stdout.write(self.style.ERROR('❌ Falha no backup dos equipamentos'))
                return
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Erro no backup: {e}'))
            import traceback
            traceback.print_exc()
            return
        
        # Encontra diretório de backup criado
        backup_dirs = [d for d in scripts_dir.iterdir() if d.is_dir() and d.name.startswith('backup_')]
        if not backup_dirs:
            self.stdout.write(self.style.ERROR('❌ Nenhum diretório de backup encontrado'))
            return
        
        # Usa o backup mais recente
        latest_backup = max(backup_dirs, key=lambda x: x.stat().st_mtime)
        self.stdout.write(f'📁 Processando backup: {latest_backup.name}')
        
        # Processa os dados usando o comando existente
        try:
            from django.core.management import call_command
            
            self.stdout.write('🔄 Processando dados para a base de dados...')
            call_command('process_existing_configs', '--force')
            
            # Verifica resultados
            total_equipment = Equipment.objects.count()
            total_configs = MplsConfiguration.objects.count()
            
            self.stdout.write(self.style.SUCCESS(f'✅ Processamento concluído!'))
            self.stdout.write(f'📊 Equipamentos: {total_equipment}')
            self.stdout.write(f'📊 Configurações: {total_configs}')
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Erro ao processar dados: {e}'))
            import traceback
            traceback.print_exc()
        
        self.stdout.write('🎉 Processamento de backups concluído!')
