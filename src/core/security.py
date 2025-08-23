from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required as dj_login_required


def admin_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_superuser:
            messages.error(request, "Acesso negado – apenas administradores.")
            return redirect("login")
        return view_func(request, *args, **kwargs)
    return _wrapped_view

# login_required pode ser usado diretamente do Django, mas para manter compatibilidade:

def login_required(view_func):
    return dj_login_required(view_func)


# ==============================
# Helpers de segurança/auditoria
# ==============================
from typing import Optional, Dict, Any
from .audit_models import AuditEvent
from .utils import get_client_ip, get_user_agent, get_correlation_id


def _audit(
    request,
    action: str,
    *,
    user=None,
    status_code: int = 200,
    success: bool = True,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Registra um AuditEvent padronizado.

    - Nunca registra senhas/tokens em metadata (aplica _mask_sensitive).
    - Usa correlation_id do middleware, se presente.
    """
    try:
        safe_metadata = _mask_sensitive(metadata or {})
        AuditEvent.objects.create(
            user=user if user is not None else (request.user if getattr(request, 'user', None) and request.user.is_authenticated else None),
            action=action,
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            path=getattr(request, 'path', '') or '',
            method=getattr(request, 'method', '') or '',
            status_code=int(status_code),
            success=bool(success),
            metadata=safe_metadata,
            correlation_id=get_correlation_id(request),
        )
    except Exception:
        # Nunca quebrar fluxo por erro de auditoria
        pass


_SENSITIVE_KEYS = {"password", "passwd", "pwd", "token", "authorization", "secret", "refresh"}


def _mask_sensitive(value: Any):
    """Masca dados sensíveis em estruturas dict/list/tuple simples."""
    try:
        if isinstance(value, dict):
            masked = {}
            for k, v in value.items():
                if isinstance(k, str) and k.lower() in _SENSITIVE_KEYS:
                    masked[k] = "***"
                else:
                    masked[k] = _mask_sensitive(v)
            return masked
        if isinstance(value, list):
            return [_mask_sensitive(v) for v in value]
        if isinstance(value, tuple):
            return tuple(_mask_sensitive(v) for v in value)
        return value
    except Exception:
        return "***" 