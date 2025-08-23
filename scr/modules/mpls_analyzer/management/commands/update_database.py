from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.contrib.auth.models import User
import os
import glob

from modules.mpls_analyzer.models import BackupProcessLog
from modules.mpls_analyzer.parsers import BackupProcessor


class Command(BaseCommand):
    help = 'Processa arquivos de backup e atualiza o banco de dados com informações MPLS'

    def add_arguments(self, parser):
        parser.add_argument(
            '--backup-dir',
            type=str,
            help='Diretório específico de backup para processar',
        )
        parser.add_argument(
            '--all-backups',
            action='store_true',
            help='Processa todos os diretórios de backup encontrados',
        )
        parser.add_argument(
            '--user',
            type=str,
            help='Nome do usuário que executou o processo (opcional)',
        )

    def handle(self, *args, **options):
        from django.conf import settings
        
        # Usa apenas o diretório de scripts
        base_dir = os.path.join(settings.BASE_DIR, 'modules', 'mpls_analyzer', 'scripts')
        
        # Determina quais diretórios processar
        backup_dirs = []
        
        if options['backup_dir']:
            backup_dir = options['backup_dir']
            if not os.path.isabs(backup_dir):
                backup_dir = os.path.join(base_dir, backup_dir)
            backup_dirs.append(backup_dir)
            
        elif options['all_backups']:
            # Busca todos os diretórios backup_*
            pattern = os.path.join(base_dir, 'backup_*')
            backup_dirs = glob.glob(pattern)
            backup_dirs = [d for d in backup_dirs if os.path.isdir(d)]
            
        else:
            # Busca o diretório de backup mais recente
            pattern = os.path.join(base_dir, 'backup_*')
            backup_dirs = glob.glob(pattern)
            backup_dirs = [d for d in backup_dirs if os.path.isdir(d)]
            if backup_dirs:
                backup_dirs = [max(backup_dirs, key=os.path.getctime)]

        if not backup_dirs:
            raise CommandError('Nenhum diretório de backup encontrado')

        # Busca usuário se especificado
        user = None
        if options['user']:
            try:
                user = User.objects.get(username=options['user'])
            except User.DoesNotExist:
                self.stdout.write(
                    self.style.WARNING(f'Usuário {options["user"]} não encontrado')
                )

        # Processa cada diretório
        processor = BackupProcessor()
        
        for backup_dir in backup_dirs:
            self.stdout.write(f'Processando diretório: {backup_dir}')
            
            # Cria log do processo
            log = BackupProcessLog.objects.create(
                started_at=timezone.now(),
                status='running',
                user=user
            )
            
            try:
                processed_files, total_files, errors = processor.process_backup_directory(backup_dir)
                
                # Atualiza log com resultados
                log.finished_at = timezone.now()
                log.status = 'completed' if not errors else 'failed'
                log.processed_files = processed_files
                log.total_files = total_files
                log.errors = '\n'.join(errors)
                log.save()
                
                # Exibe resultados
                self.stdout.write(
                    self.style.SUCCESS(
                        f'Processamento concluído para {backup_dir}:\n'
                        f'  - Arquivos processados: {processed_files}/{total_files}\n'
                        f'  - Erros: {len(errors)}'
                    )
                )
                
                if errors:
                    self.stdout.write(self.style.ERROR('Erros encontrados:'))
                    for error in errors:
                        self.stdout.write(f'  - {error}')
                
            except Exception as e:
                # Atualiza log com erro
                log.finished_at = timezone.now()
                log.status = 'failed'
                log.errors = str(e)
                log.save()
                
                raise CommandError(f'Erro ao processar {backup_dir}: {str(e)}')

        self.stdout.write(
            self.style.SUCCESS('Todos os diretórios foram processados com sucesso!')
        )