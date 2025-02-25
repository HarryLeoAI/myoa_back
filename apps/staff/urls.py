from django.urls import path
from rest_framework.routers import DefaultRouter
from . import views

app_name='staff'

router = DefaultRouter()
router.register('staff', viewset=views.StaffViewSet, basename='staff')

urlpatterns = [
    path('staff/departmtents/', views.DepartmentListView.as_view(), name="department"),
    path('staff/active/', views.ActiveStaffView.as_view(), name="active")
] + router.urls
