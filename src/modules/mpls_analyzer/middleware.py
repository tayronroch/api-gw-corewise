from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from django.utils import timezone
from .models import AccessLog, LoginAttempt
import logging

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Extrai o IP real do cliente considerando proxies"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_user_agent(request):
    """Extrai o User-Agent do request"""
    return request.META.get('HTTP_USER_AGENT', '')


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """Registra login bem-sucedido"""
    try:
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Registra no AccessLog (sistema antigo)
        AccessLog.objects.create(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            status='success',
            session_key=request.session.session_key or ''
        )
        
        # Registra no LoginAttempt (novo sistema)
        LoginAttempt.record_attempt(
            username=user.username,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )
        
        logger.info(f"Login successful for user {user.username} from {ip_address}")
    except Exception as e:
        logger.error(f"Error logging user login: {str(e)}")


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    """Registra logout"""
    if user:
        try:
            # Encontra o último log de acesso ativo e atualiza com logout
            last_login = AccessLog.objects.filter(
                user=user,
                status='success',
                logout_time__isnull=True
            ).order_by('-login_time').first()
            
            if last_login:
                last_login.logout_time = timezone.now()
                last_login.save()
            
            # Cria um novo registro de logout
            AccessLog.objects.create(
                user=user,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request),
                status='logout',
                session_key=request.session.session_key or ''
            )
            logger.info(f"Logout for user {user.username} from {get_client_ip(request)}")
        except Exception as e:
            logger.error(f"Error logging user logout: {str(e)}")


@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):
    """Registra tentativa de login falhada"""
    try:
        username = credentials.get('username', 'unknown')
        
        # Tenta encontrar o usuário para registrar o log
        from django.contrib.auth.models import User
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None
        
        failure_reason = "Credenciais inválidas"
        if user and hasattr(user, 'profile'):
            if user.profile.is_account_locked():
                failure_reason = "Conta bloqueada"
        
        AccessLog.objects.create(
            user=user,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
            status='failed',
            failure_reason=failure_reason,
            session_key=''
        )
        logger.warning(f"Login failed for username {username} from {get_client_ip(request)}: {failure_reason}")
    except Exception as e:
        logger.error(f"Error logging failed login: {str(e)}")


class AuditMiddleware(MiddlewareMixin):
    """Middleware para capturar informações de auditoria"""
    
    def process_request(self, request):
        """Adiciona informações de IP e User-Agent ao request para uso posterior"""
        request.audit_ip = get_client_ip(request)
        request.audit_user_agent = get_user_agent(request)
        return None
    
    def process_response(self, request, response):
        """Processa a resposta - pode ser usado para logs adicionais"""
        return response