from django.urls import path
from rest_framework.routers import DefaultRouter
from . import views

app_name='staff'

router = DefaultRouter()
router.register('staff', viewset=views.StaffViewSet, basename='staff')

urlpatterns = [
    path('staff/departmtents/', views.DepartmentListView.as_view(), name="department"),
    path('staff/active/', views.ActiveStaffView.as_view(), name="active"),
    path('staff/download/', views.StaffDownloadView.as_view(), name="download"),
    path('staff/upload/', views.StaffUploadView.as_view(), name="upload"),
    path('staff/nopaginationlist/', views.StaffListView.as_view(), name="npstafflist"),
    path('departmetns/<pk>/', views.DepartmentUpdateView.as_view(), name="updatedepartment")
] + router.urls
