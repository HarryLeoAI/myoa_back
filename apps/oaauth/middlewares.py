from django.utils.deprecation import MiddlewareMixin
import jwt
from django.conf import settings
from rest_framework.authentication import get_authorization_header
from rest_framework import exceptions,status
from jwt.exceptions import ExpiredSignatureError
from .models import OAUser
from django.http.response import JsonResponse
from django.contrib.auth.models import AnonymousUser

class LoginCheckMiddleware(MiddlewareMixin):
    keyword = 'JWT'
    def process_view(self, request, view_func, view_args, view_kwargs):
        if request.path == '/auth/login' or request.path.startswith(settings.MEDIA_URL):
            request.user = AnonymousUser()
            request.auth = None
            return None
        try:
            auth = get_authorization_header(request).split()

            if not auth or auth[0].lower() != self.keyword.lower().encode():
                raise exceptions.ValidationError("请传入令牌!")

            if len(auth) != 2:
                raise exceptions.AuthenticationFailed("令牌认证失败!")

            try:
                jwt_token = auth[1]
                jwt_info = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms='HS256')
                userid = jwt_info.get('userid')
                try:
                    # 绑定当前user到request对象上
                    user = OAUser.objects.get(pk=userid)
                    # HttpRequest对象：是Django内置的
                    request.user = user
                    request.auth = jwt_token
                except:
                    raise exceptions.AuthenticationFailed("用户不存在!")
            except ExpiredSignatureError:
                raise exceptions.AuthenticationFailed("令牌已过期！")
        except :
            return JsonResponse(data={"detail": "请先登录！"}, status=status.HTTP_403_FORBIDDEN)
