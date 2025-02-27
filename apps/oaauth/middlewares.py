from django.utils.deprecation import MiddlewareMixin
import jwt
from django.conf import settings
from rest_framework.authentication import get_authorization_header
from rest_framework import status
from jwt.exceptions import ExpiredSignatureError
from .models import OAUser
from django.http.response import JsonResponse
from django.contrib.auth.models import AnonymousUser

class WhiteList:
    path = [
        '/auth/login',
        '/staff/active/',
    ]

class LoginCheckMiddleware(MiddlewareMixin):
    keyword = 'JWT'

    def process_view(self, request, view_func, view_args, view_kwargs):
        # 白名单跳过认证
        if request.path.startswith(settings.MEDIA_URL) or request.path in WhiteList.path:
            request.user = AnonymousUser()
            request.auth = None
            return None

        # 获取并验证 token
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return JsonResponse(data={"detail": "请传入令牌!"}, status=status.HTTP_403_FORBIDDEN)

        if len(auth) != 2:
            return JsonResponse(data={"detail": "令牌格式错误!"}, status=status.HTTP_403_FORBIDDEN)

        # 解析 JWT 并绑定用户
        try:
            jwt_token = auth[1]
            jwt_info = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms='HS256')
            userid = jwt_info.get('userid')
            if not userid:
                return JsonResponse(data={"detail": "令牌无效，缺少用户信息!"}, status=status.HTTP_403_FORBIDDEN)

            # 获取用户
            user = OAUser.objects.get(pk=userid)
            request.user = user
            request.auth = jwt_token

        except ExpiredSignatureError:
            return JsonResponse(data={"detail": "令牌已过期！"}, status=status.HTTP_403_FORBIDDEN)
        except OAUser.DoesNotExist:
            return JsonResponse(data={"detail": "用户不存在!"}, status=status.HTTP_403_FORBIDDEN)
        except jwt.DecodeError:
            return JsonResponse(data={"detail": "令牌解析失败!"}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            # 非认证相关的异常，记录日志并抛出
            print(f"Unexpected error in LoginCheckMiddleware: {str(e)}")
            raise  # 抛出异常，让 Django 处理服务器错误

        return None