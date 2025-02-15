from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import LoginSerializer, UserSerializer, ResetPasswordSerializer
from datetime import datetime
from .authentications import generate_jwt
from rest_framework import status


class LoginView(APIView):
    """
    登录视图
    """

    def post(self, request):
        """
        登录方法
        """
        # 验证数据是否可用
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data.get('user')
            # 更新最近登录时间
            user.last_login = datetime.now()
            user.save()
            # 生成jwt_token
            token = generate_jwt(user)
            # 返回token和用户信息给前端
            return Response({'token': token, 'user': UserSerializer(user).data})
        else:
            detail = list(serializer.errors.values())[0][0]
            # drf 在返回响应, 状态码非200时, 返回的参数名叫detail而非message.
            return Response({'detail': detail}, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
    """
    重置密码
    """
    def put(self, request):
        serializer = ResetPasswordSerializer(data=request.data, context={'request': request})

        if serializer.is_valid():
            password = serializer.validated_data.get('new_password')
            request.user.set_password(password)
            request.user.save()
            return Response({'message': '密码修改成功'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail':list(serializer.errors.values())[0][0]}, status=status.HTTP_400_BAD_REQUEST)