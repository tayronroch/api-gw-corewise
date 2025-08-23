from django.urls import path
from . import views


urlpatterns = [
    path("ping/", views.ping, name="api-v1-ping"),
]

