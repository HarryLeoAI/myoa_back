from rest_framework.generics import ListAPIView
from apps.oaauth.models import OADepartment
from apps.oaauth.serializers import DepartmentSerializer
from rest_framework.views import APIView
from .serializers import CreateStaffSerializer
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings

OAUser = get_user_model()


class DepartmentListView(ListAPIView):
    queryset = OADepartment.objects.all()
    serializer_class = DepartmentSerializer

class StaffView(APIView):
    def post(self, request):
        serializer = CreateStaffSerializer(data=request.POST, context={'request': request})
        if serializer.is_valid():
            email = serializer.validated_data['email']
            realname = serializer.validated_data['realname']
            password = '111111'
            telphone = serializer.validated_data['telphone']
            department_id = request.user.department.id

            # 创建用户
            user = OAUser.objects.create_user(email=email, realname=realname, password=password, telphone=telphone, department_id=department_id)

            # 发送邮件
            send_mail(subject=f'你好,{user.realname}!欢迎加入我们!', message=f'欢迎你!', from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[email])
        else:
            return Response(data={'detail': list(serializer.errors.values())[0][0]},status=status.HTTP_400_BAD_REQUEST)