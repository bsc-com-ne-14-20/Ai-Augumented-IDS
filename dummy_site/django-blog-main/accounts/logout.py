from django.contrib.auth.views import LogoutView
from django.contrib import messages 

class CustomLogoutView(LogoutView):
    next_page = 'auth-login'
    
    def dispatch(self, request, *args, **kwargs):
        messages.success(request, "You have been logged out successfully.")
        return super().dispatch(request, *args, **kwargs)
