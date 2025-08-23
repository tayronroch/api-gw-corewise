from django.contrib.auth.models import User
from .models import AuditLog
import logging

logger = logging.getLogger(__name__)


def log_audit_action(user, action, description, request, **kwargs):
    """
    Registra uma ação de auditoria
    
    Args:
        user: Usuário que executou a ação
        action: Tipo de ação (search, report_export, etc.)
        description: Descrição detalhada da ação
        request: Request HTTP atual
        **kwargs: Dados adicionais (target_object_type, target_object_id, search_query, etc.)
    """
    try:
        ip_address = getattr(request, 'audit_ip', request.META.get('REMOTE_ADDR', ''))
        user_agent = getattr(request, 'audit_user_agent', request.META.get('HTTP_USER_AGENT', ''))
        
        audit_log = AuditLog.objects.create(
            user=user,
            action=action,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent,
            target_object_type=kwargs.get('target_object_type', ''),
            target_object_id=kwargs.get('target_object_id'),
            search_query=kwargs.get('search_query', ''),
            export_format=kwargs.get('export_format', ''),
            results_count=kwargs.get('results_count'),
            additional_data=kwargs.get('additional_data', {})
        )
        
        logger.info(f"Audit log created: {user.username} - {action} - {description}")
        return audit_log
        
    except Exception as e:
        logger.error(f"Error creating audit log: {str(e)}")
        return None


class AuditLogger:
    """Classe utilitária para facilitar o uso do sistema de auditoria"""
    
    @staticmethod
    def log_search(user, request, search_query, results_count=None):
        """Registra uma busca realizada"""
        return log_audit_action(
            user=user,
            action='search',
            description=f"Busca realizada: '{search_query}'",
            request=request,
            search_query=search_query,
            results_count=results_count
        )
    
    @staticmethod
    def log_report_export(user, request, export_format, results_count=None, report_type=None):
        """Registra exportação de relatório"""
        description = f"Relatório exportado em formato {export_format.upper()}"
        if report_type:
            description += f" - Tipo: {report_type}"
            
        return log_audit_action(
            user=user,
            action='report_export',
            description=description,
            request=request,
            export_format=export_format,
            results_count=results_count,
            additional_data={'report_type': report_type} if report_type else {}
        )
    
    @staticmethod
    def log_equipment_view(user, request, equipment_id, equipment_name):
        """Registra visualização de equipamento"""
        return log_audit_action(
            user=user,
            action='view_equipment',
            description=f"Visualizou equipamento: {equipment_name}",
            request=request,
            target_object_type='Equipment',
            target_object_id=equipment_id
        )
    
    @staticmethod
    def log_vpn_view(user, request, vpn_id, vpn_description=""):
        """Registra visualização de VPN"""
        description = f"Visualizou VPN ID: {vpn_id}"
        if vpn_description:
            description += f" - {vpn_description}"
            
        return log_audit_action(
            user=user,
            action='view_vpn',
            description=description,
            request=request,
            target_object_type='Vpn',
            target_object_id=vpn_id
        )
    
    @staticmethod
    def log_backup_process(user, request, process_type, status=None):
        """Registra processo de backup"""
        description = f"Processo de backup: {process_type}"
        if status:
            description += f" - Status: {status}"
            
        return log_audit_action(
            user=user,
            action='backup_process',
            description=description,
            request=request,
            additional_data={'process_type': process_type, 'status': status}
        )
    
    @staticmethod
    def log_config_download(user, request, equipment_name, config_date=None):
        """Registra download de configuração"""
        description = f"Download de configuração: {equipment_name}"
        if config_date:
            description += f" - Data: {config_date}"
            
        return log_audit_action(
            user=user,
            action='config_download',
            description=description,
            request=request,
            additional_data={'equipment_name': equipment_name, 'config_date': str(config_date) if config_date else None}
        )
    
    @staticmethod
    def log_user_management(user, request, action_type, target_username=None):
        """Registra ações de gerenciamento de usuários"""
        description = f"Gerenciamento de usuário: {action_type}"
        if target_username:
            description += f" - Usuário: {target_username}"
            
        return log_audit_action(
            user=user,
            action='user_management',
            description=description,
            request=request,
            additional_data={'action_type': action_type, 'target_username': target_username}
        )
    
    @staticmethod
    def log_system_settings(user, request, setting_type, description=None):
        """Registra alterações nas configurações do sistema"""
        desc = f"Configurações do sistema: {setting_type}"
        if description:
            desc += f" - {description}"
            
        return log_audit_action(
            user=user,
            action='system_settings',
            description=desc,
            request=request,
            additional_data={'setting_type': setting_type}
        )