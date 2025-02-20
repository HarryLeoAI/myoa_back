from django.urls import path
from . import views

app_name='staff'

urlpatterns = [
    path('departmtents/', views.DepartmentListView.as_view(), name="department")
]