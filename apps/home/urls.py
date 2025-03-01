from django.urls import path
from . import views

app_name = 'home'

urlpatterns = [
    path('lates/inform/', views.LatestInformView.as_view(), name='latestinform'),
    path('lates/absent/', views.LatestAbsentView.as_view(), name='latestabsent'),
    path('depatment/staffcount/', views.DepartmentStaffCount.as_view(), name='staffcount'),
]