from django.urls import path,include
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path('auth/', include('apps.oaauth.urls')), # 用户
    path('', include('apps.absent.urls')), # 考勤
    path('', include('apps.inform.urls')), #通知
    path('', include('apps.staff.urls')), # 获取所有部门
    path('image/', include('apps.image.urls')) # 上传图片
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
