from django.urls import path
from django.contrib.auth import views as auth_views
from . import views, logout 

urlpatterns = [
    path('register/',views.register, name='auth-register'),
    path('login/',auth_views.LoginView.as_view(template_name='accounts/login.html'), name='auth-login'),
    path('logout/',logout.CustomLogoutView.as_view(), name='auth-logout'),
    path('profile/', views.profile, name='auth-profile'),
    
]
