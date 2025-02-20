from django.urls import path
from . import views

app_name = 'image'

urlpatterns = [
    path('upload/', views.UploadImageView.as_view(), name="upload")
]