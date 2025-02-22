from django.urls import path
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'inform'

router = DefaultRouter()

router.register("inform", views.InformViewSet, basename='inform')

urlpatterns = [
    path('inform/onread/', views.InformReadView.as_view(), name="read")
] + router.urls
