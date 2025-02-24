from django.urls import path
from . import views

app_name='staff'

urlpatterns = [
    path('departmtents/', views.DepartmentListView.as_view(), name="department"),
    path('', views.StaffView.as_view(), name="staff"),
    path('active/', views.ActiveStaffView.as_view(), name="active")
]