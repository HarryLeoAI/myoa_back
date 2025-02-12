import jwt
import time
from django.conf import settings
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions
from jwt.exceptions import ExpiredSignatureError
from .models import OAUser


def generate_jwt(user):
    """
    生成jwt_token
    """
    expire_time = time.time() + 60 * 60 * 24 * 7
    return jwt.encode({"userid": user.pk, "exp": expire_time}, key=settings.SECRET_KEY)


class UserTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # 这里的request：是rest_framework.request.Request对象
        return request._request.user, request._request.auth


class JWTAuthentication(BaseAuthentication):
    keyword = 'JWT'

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth) == 1:
            msg = "不可用的JWT请求头!"
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = '不可用的JWT请求头!JWT Token中间不应该有空格!'
            raise exceptions.AuthenticationFailed(msg)

        try:
            jwt_token = auth[1]
            jwt_info = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms='HS256')
            userid = jwt_info.get('userid')
            try:
                # 绑定当前user到request对象上
                user = OAUser.objects.get(pk=userid)
                setattr(request, 'user', user)
                return user, jwt_token
            except:
                msg = '用户不存在!'
                raise exceptions.AuthenticationFailed(msg)
        except ExpiredSignatureError:
            msg = "JWT Token已过期!"
            raise exceptions.AuthenticationFailed(msg)
