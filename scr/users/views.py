from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from django.db import models
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import authentication_classes
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.viewsets import ModelViewSet
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes
import json
from .models import UserProfile, UserLogEvent
from .serializers import UserSerializer, CreateUserSerializer, UpdateUserSerializer
from .permissions import UserManagementPermission, RoleBasedPermission
from core.security import login_required

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("login")
        password = request.POST.get("senha")
        user = authenticate(request, username=username, password=password)
        if user:
            # Verifica MFA
            # try:
            #     profile = UserProfile.objects.get(user=user)
            #     if getattr(profile, 'mfa_enabled', False):
            #         request.session["pending_user_id"] = user.id
            #         return redirect("verify_mfa")
            # except UserProfile.DoesNotExist:
            #     pass
            login(request, user)
            return redirect("home")
        else:
            messages.error(request, "Login falhou. Verifique suas credenciais.")
    return render(request, "login.html")

@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def api_login(request):
    """
    API para autenticação via REST
    """
    try:
        data = request.data
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return Response({
                'error': 'Username e password são obrigatórios'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        user = authenticate(username=username, password=password)
        
        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'success': True,
                'message': 'Login realizado com sucesso',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                },
                'tokens': {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'error': 'Credenciais inválidas'
            }, status=status.HTTP_401_UNAUTHORIZED)
            
    except Exception as e:
        return Response({
            'error': f'Erro interno do servidor: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema(
    operation_id='user_logout',
    tags=['authentication'],
    summary='Logout de usuário',
    description='Invalida o token de refresh do usuário para realizar logout seguro',
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'refresh': {'type': 'string', 'description': 'Token de refresh para invalidar'},
            },
            'required': ['refresh']
        }
    },
    responses={
        200: {
            'description': 'Logout realizado com sucesso',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Logout realizado com sucesso'
                    }
                }
            }
        },
        500: {
            'description': 'Erro interno do servidor',
            'content': {
                'application/json': {
                    'example': {
                        'error': 'Erro interno do servidor: ...'
                    }
                }
            }
        }
    }
)
@api_view(['POST'])
@csrf_exempt
def api_logout(request):
    """
    API para logout via REST
    """
    try:
        # Invalida o token de refresh
        refresh_token = request.data.get('refresh')
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()
        
        return Response({
            'success': True,
            'message': 'Logout realizado com sucesso'
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': f'Erro interno do servidor: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def verify_mfa(request):
    # Lógica de MFA a ser implementada
    pass

@login_required
def logout_view(request):
    logout(request)
    messages.success(request, "Logout realizado com sucesso.")
    return redirect("login")

# ===== CRUD DE USUÁRIOS =====

class UserViewSet(ModelViewSet):
    """
    ViewSet completo para gerenciamento de usuários
    - Apenas administradores podem gerenciar usuários
    - Editores podem visualizar usuários
    - Viewers não têm acesso
    """
    queryset = User.objects.all().select_related('profile')
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, UserManagementPermission]
    
    def get_permissions(self):
        """
        Permissões personalizadas por ação
        """
        if self.action in ['list', 'retrieve', 'stats']:
            # Editores podem listar e ver detalhes
            permission_classes = [IsAuthenticated]
        else:
            # Apenas admins para outras ações
            permission_classes = [IsAuthenticated, UserManagementPermission]
        
        return [permission() for permission in permission_classes]
    
    def get_serializer_class(self):
        if self.action == 'create':
            return CreateUserSerializer
        elif self.action in ['update', 'partial_update']:
            return UpdateUserSerializer
        return UserSerializer
    
    def get_queryset(self):
        """Filtrar usuários baseado em permissões"""
        queryset = User.objects.all().select_related('profile')
        
        # Adicionar filtros se necessário
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                models.Q(username__icontains=search) |
                models.Q(email__icontains=search) |
                models.Q(first_name__icontains=search) |
                models.Q(last_name__icontains=search)
            )
        
        role = self.request.query_params.get('role', None)
        if role:
            queryset = queryset.filter(profile__role=role)
        
        active = self.request.query_params.get('active', None)
        if active is not None:
            is_active = active.lower() == 'true'
            queryset = queryset.filter(is_active=is_active)
        
        return queryset.order_by('-date_joined')
    
    def create(self, request, *args, **kwargs):
        """Criar novo usuário"""
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Log da criação
            UserLogEvent.objects.create(
                username=f"Created by {request.user.username}",
                success=True,
                ip=request.META.get('REMOTE_ADDR', '127.0.0.1')
            )
            
            # Retornar dados completos do usuário criado
            response_serializer = UserSerializer(user)
            return Response(
                {
                    'success': True,
                    'message': 'Usuário criado com sucesso',
                    'user': response_serializer.data
                },
                status=status.HTTP_201_CREATED
            )
        
        return Response(
            {
                'success': False,
                'message': 'Erro na validação dos dados',
                'errors': serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )
    
    def update(self, request, *args, **kwargs):
        """Atualizar usuário"""
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        
        if serializer.is_valid():
            user = serializer.save()
            
            # Log da atualização
            UserLogEvent.objects.create(
                username=f"Updated {user.username} by {request.user.username}",
                success=True,
                ip=request.META.get('REMOTE_ADDR', '127.0.0.1')
            )
            
            response_serializer = UserSerializer(user)
            return Response(
                {
                    'success': True,
                    'message': 'Usuário atualizado com sucesso',
                    'user': response_serializer.data
                }
            )
        
        return Response(
            {
                'success': False,
                'message': 'Erro na validação dos dados',
                'errors': serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )
    
    def destroy(self, request, *args, **kwargs):
        """Deletar usuário"""
        instance = self.get_object()
        
        # Não permitir auto-exclusão
        if instance.id == request.user.id:
            return Response(
                {
                    'success': False,
                    'message': 'Você não pode excluir sua própria conta'
                },
                status=status.HTTP_403_FORBIDDEN
            )
        
        username = instance.username
        instance.delete()
        
        # Log da exclusão
        UserLogEvent.objects.create(
            username=f"Deleted {username} by {request.user.username}",
            success=True,
            ip=request.META.get('REMOTE_ADDR', '127.0.0.1')
        )
        
        return Response(
            {
                'success': True,
                'message': f'Usuário {username} excluído com sucesso'
            }
        )
    
    @action(detail=True, methods=['post'])
    def toggle_status(self, request, pk=None):
        """Ativar/desativar usuário"""
        user = self.get_object()
        
        # Não permitir desativar a própria conta
        if user.id == request.user.id:
            return Response(
                {
                    'success': False,
                    'message': 'Você não pode desativar sua própria conta'
                },
                status=status.HTTP_403_FORBIDDEN
            )
        
        user.is_active = not user.is_active
        user.save()
        
        # Atualizar perfil também
        profile, created = UserProfile.objects.get_or_create(user=user)
        profile.is_active = user.is_active
        profile.save()
        
        action_text = 'ativado' if user.is_active else 'desativado'
        
        # Log da ação
        UserLogEvent.objects.create(
            username=f"{action_text.title()} {user.username} by {request.user.username}",
            success=True,
            ip=request.META.get('REMOTE_ADDR', '127.0.0.1')
        )
        
        return Response(
            {
                'success': True,
                'message': f'Usuário {user.username} {action_text} com sucesso',
                'is_active': user.is_active
            }
        )
    
    @action(detail=True, methods=['post'])
    def reset_password(self, request, pk=None):
        """Reset da senha do usuário"""
        user = self.get_object()
        new_password = request.data.get('new_password')
        
        if not new_password:
            return Response(
                {
                    'success': False,
                    'message': 'Nova senha é obrigatória'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            from django.contrib.auth.password_validation import validate_password
            validate_password(new_password, user)
        except ValidationError as e:
            return Response(
                {
                    'success': False,
                    'message': 'Senha inválida',
                    'errors': e.messages
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.set_password(new_password)
        user.save()
        
        # Log do reset
        UserLogEvent.objects.create(
            username=f"Password reset for {user.username} by {request.user.username}",
            success=True,
            ip=request.META.get('REMOTE_ADDR', '127.0.0.1')
        )
        
        return Response(
            {
                'success': True,
                'message': f'Senha do usuário {user.username} resetada com sucesso'
            }
        )
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Estatísticas dos usuários"""
        from django.utils import timezone
        from datetime import timedelta
        
        total_users = User.objects.count()
        active_users = User.objects.filter(is_active=True).count()
        inactive_users = total_users - active_users
        
        # Usuários por role
        admins = UserProfile.objects.filter(role='admin').count()
        editors = UserProfile.objects.filter(role='editor').count()
        viewers = UserProfile.objects.filter(role='viewer').count()
        
        # Usuários logados nas últimas 24h
        yesterday = timezone.now() - timedelta(days=1)
        recent_logins = User.objects.filter(last_login__gte=yesterday).count()
        
        # Novos usuários na última semana
        last_week = timezone.now() - timedelta(days=7)
        new_users = User.objects.filter(date_joined__gte=last_week).count()
        
        return Response(
            {
                'total_users': total_users,
                'active_users': active_users,
                'inactive_users': inactive_users,
                'admins': admins,
                'editors': editors,
                'viewers': viewers,
                'recent_logins': recent_logins,
                'new_users': new_users,
            }
        )
    
    @action(detail=False, methods=['get', 'put', 'patch'], url_path='profile')
    def my_profile(self, request):
        """
        Permite ao usuário visualizar e editar seu próprio perfil
        GET: Visualizar perfil atual
        PUT/PATCH: Atualizar perfil
        """
        user = request.user
        
        if request.method == 'GET':
            serializer = UserSerializer(user)
            return Response({
                'success': True,
                'user': serializer.data
            })
        
        elif request.method in ['PUT', 'PATCH']:
            # Usar UpdateUserSerializer mas permitir apenas certas alterações
            serializer = UpdateUserSerializer(user, data=request.data, partial=(request.method == 'PATCH'))
            
            if serializer.is_valid():
                serializer.save()
                response_serializer = UserSerializer(user)
                
                return Response({
                    'success': True,
                    'message': 'Perfil atualizado com sucesso',
                    'user': response_serializer.data
                })
            
            return Response({
                'success': False,
                'message': 'Erro na validação dos dados',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
