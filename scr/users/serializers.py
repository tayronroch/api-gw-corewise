# -*- coding: utf-8 -*-
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['phone', 'role', 'avatar', 'is_active', 'last_login_ip', 'created_at', 'updated_at']

class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(read_only=True)
    password = serializers.CharField(write_only=True, required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 
                 'is_active', 'date_joined', 'last_login', 'password', 
                 'confirm_password', 'profile']
        read_only_fields = ['id', 'date_joined', 'last_login']
    
    def validate(self, attrs):
        if 'password' in attrs:
            password = attrs.get('password')
            confirm_password = attrs.get('confirm_password')
            
            if not confirm_password:
                raise serializers.ValidationError({
                    'confirm_password': 'Este campo e obrigatorio quando uma senha e fornecida.'
                })
            
            if password != confirm_password:
                raise serializers.ValidationError({
                    'confirm_password': 'As senhas nao coincidem.'
                })
            
            try:
                validate_password(password)
            except ValidationError as e:
                raise serializers.ValidationError({'password': e.messages})
        
        return attrs
    
    def create(self, validated_data):
        # Remove campos que nao pertencem ao modelo User
        validated_data.pop('confirm_password', None)
        password = validated_data.pop('password', None)
        
        user = User.objects.create_user(**validated_data)
        
        if password:
            user.set_password(password)
            user.save()
        
        return user
    
    def update(self, instance, validated_data):
        validated_data.pop('confirm_password', None)
        password = validated_data.pop('password', None)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        if password:
            instance.set_password(password)
        
        instance.save()
        return instance

class CreateUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    phone = serializers.CharField(required=False, allow_blank=True)
    role = serializers.ChoiceField(choices=UserProfile.ROLE_CHOICES, default='viewer')
    
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'password', 
                 'confirm_password', 'phone', 'role']
    
    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        
        if password != confirm_password:
            raise serializers.ValidationError({
                'confirm_password': 'As senhas nao coincidem.'
            })
        
        try:
            validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError({'password': e.messages})
        
        return attrs
    
    def create(self, validated_data):
        # Extrair dados do perfil
        phone = validated_data.pop('phone', '')
        role = validated_data.pop('role', 'viewer')
        validated_data.pop('confirm_password')
        
        # Criar usuario
        user = User.objects.create_user(**validated_data)
        
        # Criar ou atualizar perfil
        profile, created = UserProfile.objects.get_or_create(user=user)
        profile.phone = phone
        profile.role = role
        profile.save()
        
        return user

class UpdateUserSerializer(serializers.ModelSerializer):
    phone = serializers.CharField(required=False, allow_blank=True)
    role = serializers.ChoiceField(choices=UserProfile.ROLE_CHOICES)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'is_active', 'phone', 'role']
    
    def validate_username(self, value):
        # Verificar se o username já existe (excluindo o usuário atual)
        if User.objects.filter(username=value).exclude(id=self.instance.id if self.instance else None).exists():
            raise serializers.ValidationError('Este nome de usuário já está em uso.')
        return value
    
    def update(self, instance, validated_data):
        # Extrair dados do perfil
        phone = validated_data.pop('phone', None)
        role = validated_data.pop('role', None)
        
        # Atualizar usuario
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Atualizar perfil
        profile, created = UserProfile.objects.get_or_create(user=instance)
        if phone is not None:
            profile.phone = phone
        if role is not None:
            profile.role = role
        profile.save()
        
        return instance