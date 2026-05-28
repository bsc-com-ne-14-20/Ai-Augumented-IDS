from django.urls import path
from .views import(
    PostListView, 
    PostDetailView,
    PostUpdateView,
    PostCreateView,
    PostDeleteView
    )
from . import views 

urlpatterns = [
    path('',PostListView.as_view(), name='feature-home'),
    path('post/<int:pk>/',PostDetailView.as_view(), name='feature-post-detail'),
    path('post/<int:pk>/update/',PostUpdateView.as_view(), name='feature-post-update'),
    path('post/<int:pk>/delete/',PostDeleteView.as_view(), name='feature-post-delete'),
    path('about/',views.about, name='feature-about'),
    path('post/new/',PostCreateView.as_view(), name='feature-post-new'),
    
]
