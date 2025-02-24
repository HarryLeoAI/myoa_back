from rest_framework.generics import ListAPIView
from apps.oaauth.models import OADepartment
from apps.oaauth.serializers import DepartmentSerializer
from rest_framework.views import APIView
from .serializers import CreateStaffSerializer
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from django.conf import settings
from utils import aeser
from django.urls import reverse
from .tasks import send_mail_task

OAUser = get_user_model()
aes = aeser.AESCipher(settings.SECRET_KEY)


class ActiveStaffView(APIView):
    def get(self, request):
        pass


class DepartmentListView(ListAPIView):
    queryset = OADepartment.objects.all()
    serializer_class = DepartmentSerializer


class StaffView(APIView):

    def send_active_email(self, email, realname):
        # 处理 AES 加密
        token = aes.encrypt(email)
        active_path = reverse("staff:active") + "?token=" + token
        active_url = self.request.build_absolute_uri(active_path)

        # 异步发送邮件
        send_mail_task.delay(email, realname, active_url)

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
            self.send_active_email(email, user.realname)

            return Response(data={'detail':'用户创建成功'},status=status.HTTP_201_CREATED)
        else:
            return Response(data={'detail': list(serializer.errors.values())[0][0]}, status=status.HTTP_400_BAD_REQUEST)
