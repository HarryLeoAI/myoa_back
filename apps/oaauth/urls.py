from django.urls import path
from . import views

app_name = 'oaauth'

urlpatterns = [
    path('login', views.LoginView.as_view(), name='login'),
    path('restpassword', views.RestPasswordView.as_view(), name='restpassword')
]
