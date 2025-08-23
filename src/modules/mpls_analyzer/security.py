from django.contrib.auth.decorators import user_passes_test, login_required
from django.contrib.auth import login
from django.shortcuts import redirect, render
from django.contrib import messages
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
# MFA temporarily disabled for development
# from django_otp import user_has_device
# from django_otp.decorators import otp_required
# from django_otp.plugins.otp_totp.models import TOTPDevice
from functools import wraps
# import qrcode
# import qrcode.image.svg
# from io import BytesIO
# import base64
import logging

logger = logging.getLogger(__name__)


def require_mfa(view_func):
    """Simplified decorator for development - only requires login"""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view


def track_login_attempts(ip_address, username=None):
    """Rastreia tentativas de login e implementa rate limiting"""
    # Em desenvolvimento, permita desabilitar via settings
    if not getattr(settings, 'RATELIMIT_ENABLE', True):
        return True, None
    cache_key_ip = f"login_attempts_ip_{ip_address}"
    cache_key_user = f"login_attempts_user_{username}" if username else None
    
    # Incrementa contador de tentativas por IP
    attempts_ip = cache.get(cache_key_ip, 0)
    cache.set(cache_key_ip, attempts_ip + 1, timeout=900)  # 15 minutos
    
    # Incrementa contador de tentativas por usuário
    if cache_key_user:
        attempts_user = cache.get(cache_key_user, 0)
        cache.set(cache_key_user, attempts_user + 1, timeout=1800)  # 30 minutos
    
    # Verifica se deve bloquear
    if attempts_ip >= 5:
        logger.warning(f"IP {ip_address} bloqueado por excesso de tentativas de login")
        return False, "Muitas tentativas de login deste IP. Tente novamente em 15 minutos."
    
    if cache_key_user and cache.get(cache_key_user, 0) >= 3:
        logger.warning(f"Usuário {username} temporariamente bloqueado por tentativas de login")
        return False, f"Muitas tentativas de login para o usuário {username}. Tente novamente em 30 minutos."
    
    return True, None


def clear_login_attempts(ip_address, username=None):
    """Limpa tentativas de login após sucesso"""
    cache_key_ip = f"login_attempts_ip_{ip_address}"
    cache_key_user = f"login_attempts_user_{username}" if username else None
    
    cache.delete(cache_key_ip)
    if cache_key_user:
        cache.delete(cache_key_user)


def log_security_event(event_type, user=None, ip_address=None, details=None):
    """Registra eventos de segurança"""
    log_message = f"SECURITY_EVENT: {event_type}"
    if user:
        log_message += f" | User: {user.username}"
    if ip_address:
        log_message += f" | IP: {ip_address}"
    if details:
        log_message += f" | Details: {details}"
    
    logger.info(log_message)


def get_client_ip(request):
    """Obtém o IP real do cliente considerando proxies"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


# MFA functions temporarily disabled for development
def setup_mfa_for_user(user):
    """MFA disabled for development"""
    return None


def generate_qr_code(device):
    """MFA disabled for development"""
    return None


def validate_password_strength(password):
    """Valida força da senha"""
    errors = []
    
    if len(password) < 12:
        errors.append("A senha deve ter pelo menos 12 caracteres.")
    
    if not any(char.isupper() for char in password):
        errors.append("A senha deve conter pelo menos uma letra maiúscula.")
    
    if not any(char.islower() for char in password):
        errors.append("A senha deve conter pelo menos uma letra minúscula.")
    
    if not any(char.isdigit() for char in password):
        errors.append("A senha deve conter pelo menos um número.")
    
    if not any(char in "!@#$%^&*(),.?\":{}|<>" for char in password):
        errors.append("A senha deve conter pelo menos um caractere especial.")
    
    # Verifica se não é uma senha comum
    common_passwords = [
        'password', '123456', '12345678', 'admin', 'administrator',
        'root', 'user', 'guest', 'test', 'demo'
    ]
    
    if password.lower() in common_passwords:
        errors.append("Esta senha é muito comum e não é segura.")
    
    return errors


def is_manager(user):
    """Verifica se o usuário é um gerente (tem acesso administrativo)"""
    if not user.is_authenticated:
        return False
    
    # Verifica se é superuser
    if user.is_superuser:
        return True
    
    # Verifica se é staff
    if user.is_staff:
        return True
    
    # Verifica se tem perfil de admin
    if hasattr(user, 'profile') and user.profile.is_admin:
        return True
    
    return False


class SecurityMiddleware:
    """Middleware personalizado para segurança adicional"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Adiciona headers de segurança
        response = self.get_response(request)
        
        # Headers de segurança adicionais
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # CSP mais restritivo
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; "
            "font-src 'self' cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response['Content-Security-Policy'] = csp
        
        return response