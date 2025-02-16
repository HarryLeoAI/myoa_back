from rest_framework.routers import DefaultRouter
from . import views

app_name = 'absent'

router = DefaultRouter()
router.register('absent', viewset=views.AbsentViewSet, basename='absent')

urlpatterns = [
] + router.urls
