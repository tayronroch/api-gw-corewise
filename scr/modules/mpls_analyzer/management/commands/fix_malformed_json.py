from django.core.management.base import BaseCommand
import os
import subprocess
import sys
from pathlib import Path


class Command(BaseCommand):
    help = 'Corrige JSONs malformados usando o script do sistema original'

    def add_arguments(self, parser):
        parser.add_argument(
            '--script',
            type=str,
            default='smart-json-fix.py',
            help='Nome do script de correção a usar'
        )
        parser.add_argument(
            '--timeout',
            type=int,
            default=600,
            help='Timeout em segundos para execução do script'
        )

    def handle(self, *args, **options):
        self.stdout.write('🔧 Iniciando correção de JSONs malformados...')
        
        # Define diretório base
        base_dir = Path(__file__).resolve().parent.parent.parent.parent
        scripts_dir = base_dir / 'mpls_analyzer' / 'scripts'
        
        if not scripts_dir.exists():
            self.stdout.write(self.style.ERROR(f'❌ Diretório de scripts não encontrado: {scripts_dir}'))
            return
        
        # Verifica script de correção
        script_name = options['script']
        script_path = scripts_dir / script_name
        
        if not script_path.exists():
            self.stdout.write(self.style.ERROR(f'❌ Script de correção não encontrado: {script_path}'))
            
            # Lista scripts disponíveis
            available_scripts = [f.name for f in scripts_dir.iterdir() if f.is_file() and f.name.endswith('.py')]
            if available_scripts:
                self.stdout.write('📋 Scripts disponíveis:')
                for script in available_scripts:
                    self.stdout.write(f'  • {script}')
            return
        
        self.stdout.write(f'📜 Usando script: {script_name}')
        
        # Executa script de correção
        try:
            self.stdout.write('⚡ Executando correção de JSONs...')
            
            result = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True,
                text=True,
                cwd=str(scripts_dir),
                timeout=options['timeout']
            )
            
            if result.returncode == 0:
                self.stdout.write(self.style.SUCCESS('✅ Correção de JSONs concluída!'))
                
                # Analisa saída para mostrar resultados
                output_lines = result.stdout.split('\n')
                success_count = 0
                failed_count = 0
                
                for line in output_lines:
                    if '✅ Corrigidos com sucesso:' in line:
                        try:
                            success_count = int(line.split(':')[1].strip())
                        except:
                            pass
                    elif '❌ Ainda com problemas:' in line or '❌ Falha:' in line:
                        try:
                            failed_count = int(line.split(':')[1].strip())
                        except:
                            pass
                
                if success_count > 0:
                    self.stdout.write(self.style.SUCCESS(f'🎯 {success_count} equipamentos corrigidos com sucesso'))
                
                if failed_count > 0:
                    self.stdout.write(self.style.WARNING(f'⚠️ {failed_count} equipamentos ainda apresentam problemas'))
                
                # Mostra saída completa
                self.stdout.write('📋 Saída completa do script:')
                self.stdout.write('─' * 50)
                for line in output_lines[-20:]:  # Últimas 20 linhas
                    if line.strip():
                        self.stdout.write(line)
                self.stdout.write('─' * 50)
                
            else:
                self.stdout.write(self.style.ERROR(f'❌ Erro na correção: {result.stderr}'))
                self.stdout.write('📋 Saída de erro:')
                self.stdout.write(result.stderr)
                
        except subprocess.TimeoutExpired:
            self.stdout.write(self.style.ERROR(f'❌ Timeout: Script demorou mais que {options["timeout"]} segundos'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Erro ao executar script: {e}'))
            import traceback
            traceback.print_exc()
        
        self.stdout.write('🎉 Processo de correção concluído!')
