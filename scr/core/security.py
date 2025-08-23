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