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
from django.views import View
from django.shortcuts import render
from urllib import parse
from django.http import HttpResponseRedirect, HttpResponseForbidden, HttpResponse
from apps.oaauth.models import UserStatusChoices

OAUser = get_user_model()
aes = aeser.AESCipher(settings.SECRET_KEY)


class ActiveStaffView(View):
    def get(self, request):
        token = request.GET.get('token')

        response = render(request, 'active.html')
        response.set_cookie('token', token)

        return response

    def post(self, request):
        token = request.COOKIES.get('token')
        if not token:
            return HttpResponseForbidden("缺少令牌，禁止访问")

        try:
            email = aes.decrypt(token)
            if email != request.POST.get('email'):
                return HttpResponseForbidden("无效令牌，禁止访问")

            user = OAUser.objects.get(email=email)
            if user.status != UserStatusChoices.UNACTIVED:
                return HttpResponseForbidden("用户状态无效，禁止访问")

            # 更新用户状态并保存
            user.status = UserStatusChoices.ACTIVED
            user.save()
            # 重定向到前端并且添加路由参数 from=back
            return HttpResponseRedirect(str(settings.FRONTEND_URL + "/login/?from=back"))

        except:
            return HttpResponseForbidden("系统错误，请联系管理员")


class DepartmentListView(ListAPIView):
    queryset = OADepartment.objects.all()
    serializer_class = DepartmentSerializer


class StaffView(APIView):

    def send_active_email(self, email, realname):
        # 处理 AES 加密
        token = aes.encrypt(email)
        active_path = reverse("staff:active") + "?" + parse.urlencode({"token": token})
        active_url = self.request.build_absolute_uri(active_path)

        # 异步发送邮件
        send_mail_task.delay(email, realname, active_url)

    def post(self, request):
        serializer = CreateStaffSerializer(data=request.data, context={'request': request})
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

            return Response(data={'detail': '用户创建成功'}, status=status.HTTP_201_CREATED)
        else:
            return Response(data={'detail': list(serializer.errors.values())[0][0]}, status=status.HTTP_400_BAD_REQUEST)
