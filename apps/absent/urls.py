from django.urls import path
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'absent'

router = DefaultRouter()
router.register('absent', viewset=views.AbsentViewSet, basename='absent')

urlpatterns = [
    path('absent/types', views.AbsentTypeView.as_view(), name="absent.types"),
    path('absent/responder', views.ResponderView.as_view(), name="absent.responder")
] + router.urls
