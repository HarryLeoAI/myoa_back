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
from django.core.mail import EmailMultiAlternatives

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

        # 配置邮箱内容
        subject = f"欢迎加入我们, {realname}!"
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = email
        html_content = f"""
        <html>
          <body>
            <h1>欢迎入职本公司!</h1>
            <p>您所属部门领导已为您创建好了OA系统账号,</p>
            <p><a href="{active_url}">请点击本链接进行账号激活!</a></p>
            <p>如果上方链接无法正确访问? 请自行复制和粘贴下方链接到浏览器地址栏中手动打开!</p>
            <p>{active_url}</p>
          </body>
        </html>
        """

        # 发送邮件
        email_sender = EmailMultiAlternatives(
            subject=subject,
            body="",  # 纯文本版本
            from_email=from_email,
            to=[to_email],
        )
        email_sender.attach_alternative(html_content, "text/html")
        email_sender.send()

    def post(self, request):
        serializer = CreateStaffSerializer(data=request.POST, context={'request': request})
        if serializer.is_valid():
            email = serializer.validated_data['email']
            realname = serializer.validated_data['realname']
            password = '111111'
            telphone = serializer.validated_data['telphone']
            department_id = request.user.department.id

            # 创建用户
            user = OAUser.objects.create_user(email=email, realname=realname, password=password, telphone=telphone,
                                              department_id=department_id)

            # 发送邮件
            self.send_active_email(email, user.realname)
        else:
            return Response(data={'detail': list(serializer.errors.values())[0][0]}, status=status.HTTP_400_BAD_REQUEST)
