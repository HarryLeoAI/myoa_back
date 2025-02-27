import json
from datetime import datetime
from urllib import parse

import pandas as pd
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.http.response import HttpResponse
from django.shortcuts import render
from django.urls import reverse
from django.views import View
from rest_framework import status
from rest_framework import viewsets, mixins, exceptions
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.oaauth.models import OADepartment
from apps.oaauth.models import UserStatusChoices
from apps.oaauth.serializers import DepartmentSerializer
from apps.oaauth.serializers import UserSerializer
from utils import aeser
from .paginations import UserPagination
from .serializers import CreateStaffSerializer
from .tasks import send_mail_task

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


class StaffViewSet(mixins.CreateModelMixin,
                   mixins.UpdateModelMixin,
                   mixins.ListModelMixin,
                   viewsets.GenericViewSet):
    queryset = OAUser.objects.all()

    def get_serializer_class(self):
        if self.request.method in ['GET', 'PUT']:
            return UserSerializer
        else:
            return CreateStaffSerializer

    pagination_class = UserPagination

    def send_active_email(self, email, realname):
        # 处理 AES 加密
        token = aes.encrypt(email)
        active_path = reverse("staff:active") + "?" + parse.urlencode({"token": token})
        active_url = self.request.build_absolute_uri(active_path)

        # 异步发送邮件
        send_mail_task.delay(email, realname, active_url)

    def create(self, request, *args, **kwargs):
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

    def get_queryset(self):
        queryset = self.queryset
        request = self.request
        department_id = int(request.query_params.get('department_id'))
        realname = str(request.query_params.get('realname'))
        date_range = request.query_params.getlist('date_range[]')

        if request.user.department.name != '董事会':
            if request.user.uid != request.user.department.leader.uid:
                raise exceptions.PermissionDenied()
            else:
                queryset = queryset.filter(department_id=request.user.department_id)
        else:
            if department_id > 0:
                queryset = queryset.filter(department_id=department_id)

        if realname != '':
            queryset = queryset.filter(realname=request.query_params.get('realname'))

        if date_range:
            try:
                start_date = datetime.strptime(date_range[0], "%Y-%m-%d")
                end_date = datetime.strptime(date_range[1], "%Y-%m-%d")
                queryset = queryset.filter(date_joined__range=(start_date, end_date))
            except Exception:
                pass

        return queryset.order_by("-date_joined").all()

    def update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return super().update(request, *args, **kwargs)


class StaffDownloadView(APIView):
    def get(self, request):
        queryset = OAUser.objects.all()
        ids = request.query_params.get('ids')

        try:
            ids = json.loads(ids)
        except:
            return Response(data={'detail': '员工参数错误!'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            if request.user.department.name != '董事会':
                if request.user.uid != request.user.department.leader.uid:
                    raise exceptions.PermissionDenied()
                else:
                    queryset = queryset.filter(department_id=request.user.department.id)

            queryset = queryset.filter(pk__in=ids)
            result = queryset.values("realname", "email", "telphone", "department__name", "date_joined", "status")

            staff_df = pd.DataFrame(list(result))
            status_mapping = {1: "已激活", 2: "待激活", 3: "已锁定"}
            staff_df["status"] = staff_df["status"].map(status_mapping)
            staff_df = staff_df.rename(columns={
                "realname": "真实姓名",
                "email": "电子邮箱",
                "telphone": "联系电话",
                "department__name": "所属部门",
                "date_joined": "入职时间",
                "status": "当前状态"
            })

            response = HttpResponse(content_type='application/xlsx')
            response['content-Disposition'] = "attachment; filename=员工信息.xlsx"

            with pd.ExcelWriter(response) as writer:
                staff_df.to_excel(writer, sheet_name='员工信息')
            return response
        except Exception as e:
            return Response(data={'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
