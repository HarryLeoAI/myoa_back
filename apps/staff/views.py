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
from rest_framework.generics import ListAPIView, UpdateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.oaauth.models import OADepartment
from apps.oaauth.models import UserStatusChoices
from apps.oaauth.serializers import DepartmentSerializer
from apps.oaauth.serializers import UserSerializer
from utils import aeser
from .paginations import UserPagination
from .serializers import CreateStaffSerializer, StaffUploadSerializer, DepartmentUpdateSerializer
from .tasks import send_mail_task
from django.db import transaction

OAUser = get_user_model()
aes = aeser.AESCipher(settings.SECRET_KEY)


def send_active_email(request, email, realname):
    # 处理 AES 加密
    token = aes.encrypt(email)
    active_path = reverse("staff:active") + "?" + parse.urlencode({"token": token})
    active_url = request.build_absolute_uri(active_path)

    # 异步发送邮件
    send_mail_task.delay(email, realname, active_url)

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
            send_active_email(request, email, user.realname)

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

class StaffUploadView(APIView):
    def post(self, request):
        # 权限检查
        if request.user.department.name != '董事会' and request.user.uid != request.user.department.leader.uid:
            return Response({'detail': '无权进行此操作'}, status=status.HTTP_403_FORBIDDEN)

        # 序列化器验证
        serializer = StaffUploadSerializer(data=request.data)
        if not serializer.is_valid():
            detail = list(serializer.errors.values())[0][0]
            return Response({'detail': detail}, status=status.HTTP_400_BAD_REQUEST)

        # 读取上传的Excel文件
        file = serializer.validated_data['file']
        required_columns = ['所属部门', '真实姓名', '电子邮箱', '联系电话']

        try:
            staff_data = pd.read_excel(file)
            # 检查必要列是否存在
            if not all(col in staff_data.columns for col in required_columns):
                missing = [col for col in required_columns if col not in staff_data.columns]
                return Response({'detail': f"缺少必要的列: {', '.join(missing)}"}, status=status.HTTP_400_BAD_REQUEST)

            users = []
            # 遍历Excel行数据
            for index, row in staff_data.iterrows():
                # 获取部门并验证
                department_name = row['所属部门']
                department = OADepartment.objects.filter(name=department_name).first()
                if not department:
                    return Response({'detail': f"部门 '{department_name}' 不存在"}, status=status.HTTP_400_BAD_REQUEST)

                # 非董事会用户只能为自己部门创建员工
                if request.user.department.name != '董事会' and department != request.user.department:
                    return Response({'detail': f'您隶属{request.user.department.name}, 无权为其他部门创建员工, 请确认Excel表格里所属部门信息是否有误!'}, status=status.HTTP_403_FORBIDDEN)

                # 检查邮箱唯一性
                email = row['电子邮箱']
                if OAUser.objects.filter(email=email).exists():
                    return Response({'detail': f"电子邮箱 '{email}' 已被使用"}, status=status.HTTP_400_BAD_REQUEST)

                # 获取其他字段
                realname = row['真实姓名']
                telphone = row['联系电话']

                # 创建用户对象
                user = OAUser(email=email, realname=realname, department=department, telphone=telphone, status=2)
                user.set_password('111111')
                users.append(user)

            # 使用事务批量创建用户
            with transaction.atomic():
                OAUser.objects.bulk_create(users)

            # 发送激活邮件
            for user in users:
                send_active_email(request, user.email, user.realname)

            count = len(users)
            return Response({'detail': f'共{count}条员工信息创建成功!'}, status=status.HTTP_201_CREATED)

        except pd.errors.EmptyDataError:
            return Response({'detail': 'Excel文件为空'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'detail': f'发生错误: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

class StaffListView(ListAPIView):
    """
    返回不分页的员工列表
    """
    queryset = OAUser.objects.order_by("date_joined").all()
    serializer_class = UserSerializer

class DepartmentUpdateView(UpdateAPIView):
    queryset = OADepartment.objects.all()
    serializer_class = DepartmentUpdateSerializer