from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import LoginSerializer, UserSerializer
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
            # print(serializer.errors)
            return Response({'message': '参数验证失败'}, status=status.HTTP_400_BAD_REQUEST)
