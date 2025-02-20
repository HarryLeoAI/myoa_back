from django.urls import path,include

urlpatterns = [
    path('auth/', include('apps.oaauth.urls')), # 用户
    path('', include('apps.absent.urls')), # 考勤
    path('', include('apps.inform.urls')), #通知
    path('staff/', include('apps.staff.urls'))
]
