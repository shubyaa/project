from django.urls import path, include, re_path
from . import views
from django.views.generic import TemplateView

from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

urlpatterns = [
    path('token/', views.MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', views.RegisterView.as_view(), name='auth_register'),
    path('', views.getRoutes),
    path('test/', views.testEndPoint),
    path('auth', include('djoser.urls')),
    path('auth', include('djoser.urls.jwt')),
]

