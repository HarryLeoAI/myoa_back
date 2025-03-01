# myoa_back 企业 OA 系统后台开发日志

- 后端基于 Django Rest Framewordk

# 创建项目和基本配置

### 创建数据库

- `create database myoa;`, 略

### 创建项目

- 新建 django 项目, 选择虚拟环境, 并且安装好所需的包:
    - `pip install mysqlclient` => mysql 数据库操作包
    - `pip install djangorestframework` => drf 包

### 配置

- `settings.py`

```python
# ...
# 时区配置
LANGUAGE_CODE = 'zh-hans'  # 简体中文

TIME_ZONE = 'UTC'  # 时区

USE_I18N = False  # 非国际化项目

USE_TZ = False  # 禁用时区

# ...
# 数据库配置
from pathlib import Path
import os

database_config = ConfigParser()
database_config.read(os.path.join(BASE_DIR, 'database.cnf'))
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': database_config.get('database', 'DB_NAME'),
        'USER': database_config.get('database', 'DB_USER'),
        'PASSWORD': database_config.get('database', 'DB_PASSWORD'),
        'HOST': database_config.get('database', 'DB_HOST'),
        'PORT': database_config.get('database', 'DB_PORT'),
    }
}

# ...
# 声明加载APP: rest_framework
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',  # 安装drf
]

# ...
# 禁用csrf中间件
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware', # 禁用CSRF
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

- 新建`~/database.cnf`

```
[database]
DB_NAME = 数据库名称
DB_USER = 数据库用户
DB_PASSWORD = 数据库密码
DB_HOST = 数据库主机,默认localhost
DB_PORT = 数据库端口,默认3306
```

> 配置文件中,所有值都不用引号,错误示范:`'root'`

- 新建`.gitignore`, 声明 git 不追踪配置文件: `database.cnf`

### github 托管

- github 新建仓库`myoa_back`
- 本地项目根路径下执行以下命令:
    - `git init` 初始化仓库
    - `git add .` 添加更改项
    - `git commit -m "项目初始化"` 初次提交
    - `git remote add origin https://github.com/HarryLeoAI/myoa_back.git` 添加远程仓库地址
    - `git push --set-upstream origin master` 推送更新到远程仓库仓库, 设置主分支

# 跨域请求配置

### django-cors-headers

- `django-cors-headers` 是一个用于处理跨源资源共享（CORS，Cross-Origin Resource Sharing）请求的 Django 中间件库。CORS
  是一种机制，允许通过浏览器从一个域访问另一个域的资源。在开发 Web 应用时，尤其是前后端分离的架构中，通常会遇到跨域请求的问题，django-cors-headers
  可以帮助解决这个问题。

### 安装

- `pip install django-cors-headers`

### 配置

- `settings.py`

```py
# ...加载app
INSTALLED_APPS = [
    # ...
    'rest_framework',
    'corsheaders',  # 加载corshearders
]

# ...加载中间件, 注意应该放在
MIDDLEWARE = [
    # ...
    # corsheaders 务必放在 CommonMiddleware 前
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    # ...
]

# ...简单配置
# cors配置
CORS_ALLOW_ALL_ORIGINS = True  # 开发阶段暂时允许所有域名跨域请求
'''
# 实际投入使用时应该配置:
CORS_ALLOW_ALL_ORIGINS = False  # 默认情况下，禁用所有跨域请求
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",  # 前端vue默认的的URL
]

# 允许请求的方法
CORS_ALLOW_METHODS = [
    'GET',
    'POST',
    'PUT',
    'DELETE',
    'PATCH',
]

# 允许的请求头
CORS_ALLOW_HEADERS = [
    'content-type',
    'authorization',
    'x-csrftoken',
]

# 如果需要携带 Cookie 或认证信息
CORS_ALLOW_CREDENTIALS = True
'''
```

# 重写 User 模型

### 溯源 User 父类

- 在 pycharm 强大的索引功能中,我们只需要通过[ctrl+鼠标左键]点击类名称,即可溯源到类的源代码
- django 自带的 User 模型位于`from django.contrib.auth.models import User`

### 重写 User 类

> 不能够直接新建一个 User, 因为以此建立的全新的 User 模型将失去 django 自带的一系列功能,包括权限认证等

- 我们应该借面向对象编程思想中的多态思想, 重写已经存在的 User 类, 使其成为我们需要的样子同时, 继承了 django 原本内置的功能
- 新建 app, oaauth : `python manage.py startapp oaauth`,
- 为了方便管理, 我们修改项目目录结构, 把所有 app 放在`~/apps/`中, pycharm 新建 python 包`apps/`并且将新建的`oaauth/`放进
  apps 中
- 在`settings.py`中安装 oaauth

```py
INSTALLED_APPS = [
    # ...
    # DRF
    'rest_framework',
    # corsheaders
    'corsheaders',
    # 项目app
    'apps.oaauth'  # 用户
]
```

- 重写 User, 在`~/apps/oaauth/models.py`

```py
from django.db import models
from django.contrib.auth.models import User, AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.contrib.auth.hashers import make_password


class UserStatusChoices(models.IntegerChoices):
    """
    用户状态
    1已激活
    2未激活
    3已锁定
    """
    ACTIVED = 1
    UNACTIVED = 2
    LOCKED = 3


class OAUserManager(BaseUserManager):
    """
    重写的 UserManager
    """
    use_in_migrations = True

    def _create_user(self, realname, email, password, **extra_fields):
        """
        创建用户
        """
        if not realname:
            raise ValueError("必须设置真实姓名!")
        email = self.normalize_email(email)
        user = self.model(realname=realname, email=email, **extra_fields)
        user.password = make_password(password)
        user.save(using=self._db)
        return user

    # 普通用户
    def create_user(self, realname, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(realname, email, password, **extra_fields)

    # 超级用户
    def create_superuser(self, realname, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("status", UserStatusChoices.ACTIVED)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("超级用户必须设置is_staff = True")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("超级用户必须设置is_superuser = True")

        return self._create_user(realname, email, password, **extra_fields)


class OAUser(AbstractBaseUser, PermissionsMixin):
    """
    重写的 User
    """

    # 配置字段
    realname = models.CharField(max_length=8, unique=False)  # 真名
    email = models.EmailField(unique=True, blank=False)  # 邮箱
    telphone = models.CharField(max_length=20, blank=True)  # 电话
    is_staff = models.BooleanField(default=True)  # django自带, 是否是员工, 默认为是
    is_active = models.BooleanField(default=True)  # django自带, 是否激活, 默认为是
    status = models.IntegerField(choices=UserStatusChoices, default=UserStatusChoices.UNACTIVED)  # 用户状态,默认为未激活
    date_joined = models.DateTimeField(auto_now_add=True)  # 新增时自动添加当前时间

    objects = OAUserManager()

    EMAIL_FIELD = "email"
    # USERNAME_FIELD 是用来做鉴权的, 作为 authenticate() 中的username参数
    USERNAME_FIELD = "email"  # 重写的User模型中, 我们用邮箱作为登录账号
    # REQUIRED_FIELDS 指定哪些字段是必须要传入的, 但是不能重复包含EMAIL_FIELD和USERNAME_FIELD已经设置过的值
    REQUIRED_FIELDS = ['realname', 'password']

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def get_full_name(self):
        return self.realname

    def get_short_name(self):
        return self.realname
```

- 再在`settings.py`中声明, 本项目使用的是自定义的 User 类, OAUser

```py
# ...
# 覆盖django自带的user模型
AUTH_USER_MODEL = 'oaauth.OAUser'
```

- 创建迁移脚本, 执行迁移命令 `python manage.py makemigrations` & `... migrate`
- 测试,创建超级用户`python mange.py createsuperuser`, 输入相应信息..., ok!

### shortuuid 替代主键

- 安装: `pip install shortuuid` ? 不方便
- 使用 django 专属的 `pip install django-shortuuidfield`, 安装时自动安装上面的依赖
- 编辑`~/apps/oaauth/models.py`

```py
# ...
# 导入 ShortUUid
from shortuuidfield import ShortUUIDField


# 修改User模型的主键
class OAUser(AbstractBaseUser, PermissionsMixin):
    # ...
    # 配置字段
    uid = ShortUUIDField(primary_key=True)  # 主键:uid
    # ...
```

- 重建数据库, 删除 `0001_initial.py`后再次执行迁移

# 部门相关

> 项目逻辑: OA 系统中最高权力中心为董事会, 其次有各业务部门, 各业务部门中有一个 leader(直接领导), 一个 manager(
> 董事会经理), 一个 leader 只领导一个部门, 一个董事会经理则管理多个部门.

### 模型实现

- `~/apps/oaauth/models.py`

```py
class OADepartment(models.Model):
    """
    部门表
    """
    name = models.CharField(max_length=64)  # 部门名称
    intro = models.CharField(max_length=256)  # 部门简介
    leader = models.OneToOneField(OAUser, on_delete=models.SET_NULL, null=True, related_name='leader_department',
                                  related_query_name='leader_department')  # 领导1:1部门, 一个直接领导人只直接领导一个部门
    manager = models.ForeignKey(OAUser, on_delete=models.SET_NULL, null=True, related_name='manager_departments',
                                related_query_name='manager_departments')  # 经理1:n部门, 一个董事会经理可以管理多个部门


# User 模型中再添加外键
# ...
department = models.ForeignKey('OADepartment', null=True, on_delete=models.SET_NULL, related_name='department_staffs',
                               related_query_name='department_staffs')  # 员工n:1部门, 一个员工只隶属于一个部门
# ...
```

- 更新迁移文件,执行迁移,略

### 部门数据初始化

- 想要通过自定义命令`python manage.py [自定义命令]`创建部门初始化数据,需要以下步骤
    1. 在相关 app 下新建 python 包`app/management`, 再在这个包下面新建`app/management/commands`
    2. 新建任意名称的 python 文件, **注意:**该名称就对应`python manage.py [python文件名称]`,
       这里起名叫做`initdepartments.py`
  ```py
  from django.core.management.base import BaseCommand # 导命令包
  from apps.oaauth.models import OADepartment # 导模型
  # 类名称不可变,必须叫Command,必须继承BaseCommand
  class Command(BaseCommand):
      # 函数名称不可变,必须叫handle
      def handle(self, *args, **options):
          # 初始化部门数据
          boarder = OADepartment.objects.create(name='董事会', intro='董事会')
          developer = OADepartment.objects.create(name='研发部', intro='产品设计,技术开发')
          operator = OADepartment.objects.create(name='运营部', intro='产品和客户运营')
          salar = OADepartment.objects.create(name='销售部', intro='产品销售')
          human_resource = OADepartment.objects.create(name='人事部', intro='员工的招聘,培训,考核')
          finance = OADepartment.objects.create(name='财务部', intro='财会业务')
          # self.stdout.write('命令执行完毕后的提示信息')
          self.stdout.write('部门数据初始化成功!')
  ```
    3. `settings.py`中确保该 app 已安装
    4. 执行命令`python manage.py initdepartments`, 发现已经创建好了上面的数据

### 用户数据初始化,并指定部门

- 自定义命令`~/apps/oaauth/management/commands/initusers.py`

```py
from django.core.management.base import BaseCommand
from apps.oaauth.models import OAUser, OADepartment


class Command(BaseCommand):
    def handle(self, *args, **options):
        # 获取部门
        boarder = OADepartment.objects.get(name='董事会')
        developer = OADepartment.objects.get(name='研发部')
        operator = OADepartment.objects.get(name='运营部')
        salar = OADepartment.objects.get(name='销售部')
        human_resource = OADepartment.objects.get(name='人事部')
        finance = OADepartment.objects.get(name='财务部')

        # 董事会成员, 都是superuser
        chairman = OAUser.objects.create_superuser(email='harry.leo.ai@gmail.com', realname='刘浩宇', password='111111',
                                                   department=boarder)  # 董事会主席
        vice_chairman = OAUser.objects.create_superuser(email='harry_leo_ai@qq.com', realname='刘浩', password='111111',
                                                        department=boarder)  # 副主席

        # 各部门leader, 都是普通用户
        # 研发部
        zhang_san = OAUser.objects.create_user(email='zhangsan@qq.com', realname='张三', password='111111',
                                               department=developer)
        # 运营部
        li_si = OAUser.objects.create_user(email='lisi@qq.com', realname='李四', password='111111', department=operator)
        # 销售部
        wang_wu = OAUser.objects.create_user(email='wangwu@qq.com', realname='王五', password='111111',
                                             department=salar)
        # 人事部
        zhao_liu = OAUser.objects.create_user(email='zhaoliu@qq.com', realname='赵六', password='111111',
                                              department=human_resource)
        # 财务部
        sun_qi = OAUser.objects.create_user(email='sunqi@qq.com', realname='孙七', password='111111',
                                            department=finance)

        # 指定部门的 leader 和 manager
        boarder.leader = chairman
        boarder.manager = None

        # 董事长刘浩宇管理 研发, 运营, 销售部
        developer.leader = zhang_san
        developer.manager = chairman

        operator.leader = li_si
        operator.manager = chairman

        salar.leader = wang_wu
        salar.manager = chairman

        # 副董事长刘浩管理 人事部 和 财务部
        human_resource.leader = zhao_liu
        human_resource.manager = vice_chairman

        finance.leader = sun_qi
        finance.manager = vice_chairman

        boarder.save()
        developer.save()
        operator.save()
        salar.save()
        human_resource.save()
        finance.save()

        self.stdout.write('初始用户创建成功!')
```

- 执行命令`python manage.py initusers`

# 后台登录实现

> 要求前端 POST 请求该 API, 请求体带上正确的邮箱密码后, 返回 JWT_TOKEN 以及用户信息

### jwt 包的安装和生成 jwt_token 的实现

- 安装:`pip install PyJWT`
- 新建`~/apps/oaauth/authentications.py`

```python
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
```

> 该代码反复使用,可以保存以备复制粘贴

### 序列化的实现

> 需要序列化的有:登录序列化(jwt_token), 用户序列化(user), 以及在 user,即严重通过且登录成功的用户信息中,还带有其部门的相关信息.

- 新建`~/apps/oaauth/serializers.py`

```python
from rest_framework import serializers
from .models import OAUser, UserStatusChoices, OADepartment


class LoginSerializer(serializers.Serializer):
    """
    登录序列化
    """
    email = serializers.EmailField(required=True)  # 邮箱:必填
    password = serializers.CharField(max_length=32, min_length=6)  # 密码

    # 校验邮箱和密码
    def validate(self, attrs):
        # 提取attrs中的邮箱和密码
        email = attrs.get('email')
        password = attrs.get('password')

        # 如果其存在
        if email and password:
            # 通过邮箱提取用户信息
            user = OAUser.objects.filter(email=email).first()
            # 如果取不到
            if not user:
                raise serializers.ValidationError('请输入正确的邮箱!')
            # 如果取出后校验密码不正确
            if not user.check_password(password):
                raise serializers.ValidationError('请输入正确的密码!')
            # 如果用户未激活
            if user.status == UserStatusChoices.UNACTIVED:
                raise serializers.ValidationError('用户尚未激活,请联系管理员!')
            # 如果用户被锁定
            if user.status == UserStatusChoices.LOCKED:
                raise serializers.ValidationError('用户已被锁定,请联系管理员!')

            # 为了减少再次执行SQL语句, 直接把user放进attrs的参数中,就以user为下标
            attrs['user'] = user

        # 如果请求体中邮箱和密码不存在
        else:
            raise serializers.ValidationError('请务必输入邮箱和密码!')

        return attrs


class DepartmentSerializer(serializers.ModelSerializer):
    """
    部门模型序列化
    """

    class Meta:
        model = OADepartment
        fields = "__all__"


class UserSerializer(serializers.ModelSerializer):
    """
    用户模型序列化
    """
    department = DepartmentSerializer()  # 通过序列化嵌套, 获取详细的部门信息, 而不再单是一个外键:部门id

    class Meta:
        model = OAUser
        exclude = ['password', 'groups', 'user_permissions']
```

> 注意登录序列化, 返回的并不是模型的数据, 所以只用继承`Serializer`

### 视图层实现, 以及配置路由

- 视图`~/apps/oaauth/views.py`

```python
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
```

> 这里登录不存在增删改查, 不需要用 ViewSet 视图集, 直接继承 APIView 即可

- app 路由 `~/apps/oaauth/urls.py`

```python
from django.urls import path
from . import views

app_name = 'oaauth'

urlpatterns = [
    path('login', views.LoginView.as_view(), name='login')
]

```

- 主路由 `~/myoa_back/urls.py`

```python
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('apps.oaauth.urls'))
]
```

### 使用 postman 测试是否可用

- 打开 postman, 新建集合`myoa_back`, 再集合下新建请求`login`
    - 请求方式: `post`
    - 请求地址: `http://localhost:8000/auth/login`
    - 请求体,`x-www-form-urlencoded`, 填写预先设置好的邮箱和密码
- 请求后返回一个带`jwt_token`和`user`的 json, 成功

### 完善登录错误的提示信息

- `~/apps/oaauth/views.py` 中的 `LoginView.post()` 方法

```python
# ...
else:
detail = list(serializer.errors.values())[0][0]  # 要这样提取serializer.errors: dict.valuse()获取value干掉key, list()变成数组, 取下标
# drf 在返回响应, 状态码非200时, 返回的参数名叫detail而非message.
return Response({'detail': detail}, status=status.HTTP_400_BAD_REQUEST)
```

# 后端登录认证

> 前端此时已经完成了页面的基础架构, 前端登录的实现(登陆页面表单请求`~/apps/oaauth/views.py`中的`LoginView.post()`),
> 在邮箱和密码正确时取得 `jwt_token` 和 `user` 信息存储在浏览器中, 并且通过`Vue.路由守卫`实现前端的访问限制(
> 必须登录才能访问), 但是后端依旧可以被随便请求接口, 所以我还需要给项目后端增加认证

- 在`settings.py` 中配置 `REST_FRAMEWORK`

```py
# DRF 配置项
REST_FRAMEWORK = {
    # 指定默认认证类
    'DEFAULT_AUTHENTICATION_CLASSES': ['apps.oaauth.authentications.JWTAuthentication']
}
```

### 两种解决思路

1. 导入`from rest_framework.permissions import IsAuthenticated`,
   然后在每个需要登录才能访问的类视图里声明`permission_class=IsAuthenticated`
2. 导入`IsAuthenticated`后, 写一个父类, 里面声明`permission_class=IsAuthenticated`, 然后需要登录的接口继承这个类.

### 最优解: 中间件

> 仔细分析本项目, 作为一个 OA 系统, 用户想要访问任何页面,不都是必须要登录的吗?(除了登录页面)

- 什么是中间件? 1, 在请求达到视图前做一些事情. 2, 在响应返回浏览器之前做一些事情.

- 新建中间件`~/apps/oaauth/middlewares.py`, 以下是全部代码

```py
from django.utils.deprecation import MiddlewareMixin  # django官方自己的中间件父类
# 我们在要在中间件里实现与JWTAuthentication相同的事, 所以以下这些包都需要
import jwt  # jwt包
from django.conf import settings  # 设置,要用到里面的 SECRET_KEY
from rest_framework.authentication import get_authorization_header  # 获取请求头里的认证数据
from rest_framework import exceptions, status  # drf异常和状态码
from jwt.exceptions import ExpiredSignatureError  # jwt超时验证
from .models import OAUser  # 重写的USER模型
# 这两个类比较特殊
from django.http.response import JsonResponse  # 首先中间件验证出错必须返回django自己的response
from django.contrib.auth.models import

AnonymousUser  # 需要匿名用户是因为, 访问login页面时本来就没有request.user, 所以django会报错说request没有user属性(具体在authentications.py中)


class LoginCheckMiddleware(MiddlewareMixin):
    """
    关于中间件
        1, 首先必须继承MiddlewareMixin
        2, 中间件的函数只能两个返回值
            - None: 继续执行下一步
            - HttpResponse / JsonResponse: 拒绝进行下一步, 中间件挡住
    """
    keyword = 'JWT'

    # process_view(self, 请求, 视图函数, 视图参数, 视图可变参数): 在请求到达视图前执行:
    def process_view(self, request, view_func, view_args, view_kwargs):
        # 首先是登录页面, 说明一切正常
        if request.path == '/auth/login':
            # 为了防止报错, 所以给request.user属性设置为匿名用户
            request.user = AnonymousUser()
            # reqeust.auth 设置为空
            request.auth = None
            # 返回 None, 一切正常, 进入下一步
            return None
        # 如果不是登录页面, 开始尝试

    try:
        # 复习JWT: 生成JWT认证令牌:jwt.encode({载荷对象}, 密钥, 签名算法algorithm='HS256')
        # 载荷对象里面就是{"userid": user.pk, "exp": expire_time} 即用户主键+过期时间
        # 所以从请求头里获取了这个JSON字符串,我们需要拆分成数组
        # get_authorization_header(request)获取 JWT 并且拆分.split()
        auth = get_authorization_header(request).split()

        # 如果没有 JWT, 或者 JWT 解码后小写的第一个单词, 不是 'jwt'
        if not auth or auth[0].lower() != self.keyword.lower().encode():
            raise exceptions.ValidationError("请传入JWT!")

        # 如果JWT的长度只有1, 格式不正确
        if len(auth) == 1:
            raise exceptions.AuthenticationFailed("不可用的JWT请求头!")
        # 同样,JWT的长度大于2, 说明.split()拆的时候,多了一个空格
        elif len(auth) > 2:
            raise exceptions.AuthenticationFailed("不可用的JWT请求头！JWT Token中间不应该有空格!")

        """
        # 所以jwt作为json字符串调用split()方法拆成数组之后,长度只能为2才对,因此可以把上面两句这么写
        if len(auth) != 2:
            raise exceptions.AuthenticationFailed("令牌认证失败!")
        """

        try:
            # auth[1] 也就是 token
            jwt_token = auth[1]
            # 解码token jwt.decode(token, 密钥, 签名算法algorithms='HS256')
            jwt_info = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms='HS256')
            # 解码完了 jwt_info 就是一个存储着 userid 和 过期时间的对象了, 也就是 jwt.encode()的第一个参数:载荷对象
            # 获取载荷对象的userid属性
            userid = jwt_info.get('userid')
            try:
                # 再根据userid调用OAuser模型,终于取得了用户的信息
                user = OAUser.objects.get(pk=userid)
                # 绑定信息到 request 上面
                request.user = user
                request.auth = jwt_token
            # 如果对象不存在
            except:
                # 报错
                raise exceptions.AuthenticationFailed("用户不存在!")
        # 或者JWT.exp超时过期了
        except ExpiredSignatureError:
            # 报错
            raise exceptions.AuthenticationFailed("令牌已过期！")
        # 或者压根就没法从请求头里取到任何JWT信息, 说明没有登录
    except:
        return JsonResponse(data={"detail": "请先登录！"}, status=status.HTTP_403_FORBIDDEN)
```

- 写好中间件后,还要在`settings.py`中加载, 同时为了防止重复验证, 重新配置`REST_FRAMEWORK`

```py
# ...
MIDDLEWARE = [
    # ...
    'apps.oaauth.middlewares.LoginCheckMiddleware'
]
# DRF 配置项
REST_FRAMEWORK = {
    # 先前用这个
    # 'DEFAULT_AUTHENTICATION_CLASSES': ['apps.oaauth.authentications.JWTAuthentication']
    # 现在用这个
    'DEFAULT_AUTHENTICATION_CLASSES': ['apps.oaauth.authentications.UserTokenAuthentication']
}
```

- 在`~/apps/oaauth/authentications.py` 中完成 `UserTokenAuthentication` 认证类:

```py
class UserTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        return request._request.user, request._request.auth
```

> 这里需要注意, 我们现在在和两个 request 打交道, 一个是 `django.http.request.Request` 的实例, 一个是`DRF`
> 封装了前面的`Request`形成的`request`, 所以想要通过 drf.request 获取 django.request, 就需要`request._request`

- 我们这里什么都没验证, 因为到请求跑到这里来之前, 必须经过中间件`LoginCheckMiddleware.process_view()`方法,
  而该方法已经帮我们完成了验证, 现在就只需要把`user`和`auth`交给`request`对象, 然后所有视图接口的 request 里面就都有了
  user 和 auth 两个属性供后续使用

- 测试, 在`~/apps/oaauth/views.py`中创建一个接下来要完成的视图`RestPassword`
  > 接下来开发的接口: 重置密码,现在先用于测试后台认证是否生效

```py
class RestPasswordView(APIView):
    def get(self, request):
        return Response({'message': '成了!'}, status=status.HTTP_200_OK)
```

- 配置路由 `~apps/oaauth/urls.py`

```py
# ...
path('restpassword', views.RestPasswordView.as_view(), name='restpassword')
```

- 使用`Postman`进行测试
    1. POST 请求接口`/auth/login`, 输入正确的邮箱和密码, 拿到 TOKEN, 复制
    2. GET 请求接口`/auth/restpassword`, 如果不在`Headers`里带上正确的`Authorization`, 那么会提示`请先登录`,要想访问:

    - key = `Authorization`, value = `JWT` + `空格` + `复制的TOKEN`

### 给后台系统"瘦身"

> `settings.py` 里面有很多自带的 app, 中间件, 模板我不需要, 他们非必要的存在会影响项目的性能: 比如中间件部分,
> 每次发送任何请求或者做出任何响应都要经过一些不必要的中间件.

- 编辑`settings.py`

```py
# app 部分
INSTALLED_APPS = [
    # 'django.contrib.admin', # django自带的后台管理,不需要
    'django.contrib.auth',
    'django.contrib.contenttypes',
    # 'django.contrib.sessions', # 不用 cookie & session, 不需要
    # 'django.contrib.messages', # django自带的消息提示, 不需要
    'django.contrib.staticfiles',
    # DRF
    'rest_framework',
    # corsheaders
    'corsheaders',
    # 项目app
    'apps.oaauth'  # 用户
]

# 中间件部分
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # 'django.contrib.sessions.middleware.SessionMiddleware', # 不用 cookie & session, 不需要
    # corsheaders 务必放在 CommonMiddleware 前
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    # # 'django.middleware.csrf.CsrfViewMiddleware', # csrf_token, 不需要, 最开始就注销了
    # 'django.contrib.auth.middleware.AuthenticationMiddleware', # 用户认证, 不需要, 自己写好了
    # 'django.contrib.messages.middleware.MessageMiddleware', # django自带的消息系统, 不需要
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'apps.oaauth.middlewares.LoginCheckMiddleware'
]

# 模板配置部分
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates']
        ,
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                # 'django.contrib.messages.context_processors.messages', # 消息系统, 不需要
            ],
        },
    },
]
```

> 注释完了会报错, 是因为总路由没有干掉 `admin` 相关,解决后重启项目即可

# 修改密码

### 后端接口实现

- 在`~/apps/oaauth/serializers.py` 中新建`RestPasswordSerializer`类, 用于数据验证

```python
from rest_framework import serializers, exceptions


# ...

class ResetPasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=30, min_length=6)
    new_password = serializers.CharField(max_length=30, min_length=6)
    check_new_password = serializers.CharField(max_length=30, min_length=6)

    def validate(self, attrs):
        old_password = attrs['old_password']
        new_password = attrs['new_password']
        check_new_password = attrs['check_new_password']

        if new_password != check_new_password:
            raise exceptions.ValidationError('两次密码输入不一致')

        if new_password == old_password:
            raise exceptions.ValidationError('新旧密码相同!')

        # 想要取实例序列化时传入在context的参数, 直接 `self.context['键名'].数据` 即可
        user = self.context['request'].user
        if not user.check_password(old_password):
            raise exceptions.ValidationError('旧密码错误!')

        return attrs
```

> 复习: serializer 是 drf 提供的序列化, 主要功能:1, 把ORM对象转为JSON. 2, 实现和django.form类似的数据验证功能

- 完善视图层类视图(接口) `RestPasswordView`

```python
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
            return Response({'detail': list(serializer.errors.values())[0][0]}, status=status.HTTP_400_BAD_REQUEST)
```

> 先开始把`Reset`写成`rest`了, 一开始也用的`post`修改, 现在改`put`了

# 考勤

### 创建app

- 执行命令`python manage.py startapp absent`
- 把新建app的目录拖到`~/apps/~`下
- 在`~/apps/absent/`下创建`urls.py`并编辑,指定app_name:`app_name = 'absent'`
- `settings.py`中安装app

```python
INSTALLED_APPS = [
    # ...
    # DRF
    'rest_framework',
    # 跨域请求
    'corsheaders',
    # 项目app
    'apps.oaauth',  # 用户
    'apps.absent'  # 考勤
]
```

### 模型

- 编辑 `~/apps/absent/models.py`

```python
from django.db import models
from django.contrib.auth import get_user_model

OAUser = get_user_model()


class AbsentStatusChoices(models.IntegerChoices):
    """
    请假状态
    1审批中
    2审核通过
    3拒绝
    """
    REVIEW = 1
    AGREED = 2
    REJECT = 3


class AbsentType(models.Model):
    """
    请假类型
    """
    name = models.CharField(max_length=64)
    create_time = models.DateTimeField(auto_now_add=True)


class Absent(models.Model):
    """
    考勤
    """
    # 请假标题
    title = models.CharField(max_length=128)
    # 请假内容
    content = models.TextField()
    # 请假类型
    absent_type = models.ForeignKey(AbsentType, on_delete=models.CASCADE, related_name='absents',
                                    related_query_name='absents')
    # 请假发起人
    requester = models.ForeignKey(OAUser, on_delete=models.CASCADE, related_name='my_absents',
                                  related_query_name='my_absents')
    # 请假审批人
    responder = models.ForeignKey(OAUser, on_delete=models.CASCADE, related_name='sub_absents',
                                  related_query_name='sub_absents', null=True)
    # 请假状态
    status = models.IntegerField(choices=AbsentStatusChoices, default=AbsentStatusChoices.REVIEW)
    # 请假起始日期
    start_date = models.DateField()
    # 请假结束日期
    end_date = models.DateField()
    # 请假发起时间
    create_time = models.DateTimeField(auto_now_add=True)
    # 审批回复内容
    response_content = models.TextField(blank=True)
```

- 需要注意:
    - 引入用户模型是`from django.contrib.auth import get_user_model`,而非`from apps.oaauth.models import OAuser`
    - 在`Absent`模型中, 我有两个外键都是关联OAuser,一个请假发起人,一个请假审批人,
      所以一定要给这两个字段指定不同的`related_name`和`related_query_name`.
    - 请假审批人可以为空, 因为董事会成员休假不再需要上级再审批了
    - (请假开始日期,请假结束日期) 和请假发起时间是不同的, 请假发起时间是这条记录创建的时间.
    - 审批回复内容可以为空(没审批前肯定是空)
- 创建迁移, 迁移建表, 略

### 序列化

- 新建`~/apps/absent/serializers.py`

```python
from rest_framework import serializers
from .models import Absent, AbsentType
from apps.oaauth.serializers import UserSerializer


class AbsentTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = AbsentType
        fields = "__all__"


class AbsentSerializer(serializers.ModelSerializer):
    absent_type = AbsentTypeSerializer(read_only=True)
    absent_type_id = serializers.IntegerField(write_only=True)
    requester = UserSerializer(read_only=True)
    responder = UserSerializer(read_only=True)

    class Meta:
        model = Absent
        fields = "__all__"

    def create(self, validated_data):
        """发起请假"""
        pass

    def update(self, instance, validated_data):
        """审批请假"""
        pass

```

- `read_only` 只读, ORM转字典再转JSON时, 该字段才会被序列化
- `write_only` 只写, 前端上传到request.data里后, request.data作为参数传给序列化类进行实例创建时,该字段才会被序列化接收并转换为ORM模型里的指定字段

> 也就是说,只给前端看的: `read_only`

> 前端必须要写入的: `write_only`(通常是外键字段.id)

- 必须要重写`create`和`update`: 因为请假和审批都和User有关, User又只在request里, 后面完善

# 视图

- `~/apps/absent/views.py`

```python
from rest_framework import viewsets, mixins
from .models import Absent, AbsentType, AbsentStatusChoices


class AbsentViewSet(mixins.CreateModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    mixins.ListModelMixin,
                    viewsets.GenericViewSet):
    """
    请假功能视图集
    """
    queryset = Absent.objects.all()
    serializer_class = None
```

- 不直接继承`viewsets.ModelView`的原因是项目不需要`详情页`, 后续任何时候不需要任何功能,都可以这么写视图集:挑选需要的继承Mixin,
  最后继承`viewsets.GenericViewSet`(视图集初始化)

### 路由

- `~/apps/absent/urls.py`

```python
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'absent'

router = DefaultRouter()
router.register('absent', viewset=views.AbsentViewSet, basename='absent')

urlpatterns = [
              ] + router.urls
```

> 视图集必须这样: 注册后拼接到urlpatterns里

- 主路由 `~/myoa_back/urls.py`

```python
from django.urls import path, include

urlpatterns = [
    path('auth/', include('apps.oaauth.urls')),  # 用户
    path('', include('apps.absent.urls'))  # 考勤
]
```

### 完善序列化

1. 修复bug, 判断`absent_type_id`是否存在, 万一有人直接在form.data里面带上不存在的`absent_type_id`, 就会引发程序bug
2. 重写`create()`和`update()`函数, 一是因为表单数据直接传过来, 请求体里是不带user属性的, 必须从请求头里面取.
   二是因为还要判断请假发起人的审批者到底是谁. 同样,审批者也需要登录,也需要判断他有没有权限审批某个请假请求.

- 完整的序列化代码`~/apps/absent/serializers.py`

```python
# 导入drf.序列化包, 异常包
from rest_framework import serializers, exceptions
# 模型
from .models import Absent, AbsentType, AbsentStatusChoices
# 导入用户包
from apps.oaauth.serializers import UserSerializer
# 导入公共函数包
from .utils import get_responder


class AbsentTypeSerializer(serializers.ModelSerializer):
    """
    考勤(请假)类型序列化
    """

    class Meta:
        model = AbsentType
        fields = "__all__"


class AbsentSerializer(serializers.ModelSerializer):
    """
    考勤序列化
    """
    absent_type = AbsentTypeSerializer(read_only=True)
    absent_type_id = serializers.IntegerField(write_only=True)
    requester = UserSerializer(read_only=True)
    responder = UserSerializer(read_only=True)

    # 完善: 判断传入的考勤类型是否存在
    def validate_absent_type_id(self, value):
        if not AbsentType.objects.filter(pk=value).exists():
            raise exceptions.ValidationError("考勤类型不存在！")
        return value

    class Meta:
        model = Absent
        fields = "__all__"

    # 重写创建考勤(发起请假)方法
    def create(self, validated_data):
        """发起请假"""
        # 获取request请求信息, 我需要里面的user
        request = self.context['request']
        # 请假发起者
        user = request.user
        # 利用公共函数库里的get_responder()获取当前用户的审批者
        responder = get_responder(user)

        # 请假状态判断: 如果没有审批者, 说明是公司老大, 不需要审批请假直接通过
        if responder is None:
            validated_data['status'] = AbsentStatusChoices.AGREED
        # 否则新创建的考勤必须是待审批状态
        else:
            validated_data['status'] = AbsentStatusChoices.REVIEW

        # 写入数据库(**validated_data, 更多可变参数)
        return Absent.objects.create(**validated_data, requester=user, responder=responder)

    # 重写请假审核方法
    def update(self, instance, validated_data):
        """审批请假"""
        # 获取当前登录用户
        request = self.context['request']
        user = request.user

        # 先判断:只有待审核的考勤才能被修改(审核)
        if instance.status != AbsentStatusChoices.REVIEW:
            raise exceptions.APIException(detail='禁止修改!')

        # 然后判断本条考勤的审核者是不是当前登录用户
        if instance.responder.uid != user.uid:
            raise exceptions.AuthenticationFailed(detail='没有权限!')

        # 更新审核信息(前端传入status要么同意AGREED,要么拒绝REJECT)
        instance.status = validated_data['status']
        instance.response_content = validated_data['response_content']
        instance.save()

        return instance
```

- 这些方法都是重写`ModelSerializer`里已经定义好的方法, 要重写的原因是因为我有更复杂的逻辑.但其参数不会变.
- 更新`update`和创建`create`最大的不同是, update多一个`instance`参数, 这个参数进入函数内部, 也就是当前要修改的实例ORM对象,
  它从哪里来呢? 就从路由的参数里来.
    - 新增的路由是`POST`请求`localhost:8000/absent`
    - 修改的路由是`PUT`请求`localhost:8000/absent/absent.id`
- **公共函数库**: 不仅在`serializers.py`里我需要用到一个功能:提取当前用户的审批者, 在`views.py`里我也需要用到这个函数,
  所以我把这个函数写在一个新建的文件里`~/apps/absent/utils.py`

```python
"""
absent公共函数库
"""


def get_responder(user):
    """
    :param user:  当前登录用户, 请从 request.user中获取
    :return:      当前用户发起考勤(请假)时的审批者
    """
    # 如果当前用户所在部门的领导是他自己
    if user.department.leader.uid == user.uid:
        # 同时他的部门叫做董事会, 说明这个人就是公司老板
        if user.department.name == '董事会':
            # 那么他请假自然不需要任何人同意
            responder = None
        else:
            # 但如果他是部门领导,但部门不是董事会,他请假就需要董事会分管他所在部门的领导进行审批
            responder = user.department.manager
    else:
        # 如果他连部门领导都不是, 也就是牛马, 牛马请假需要部门领导审批
        responder = user.department.leader

    # 返回当前用户的审批人
    return responder
```

### 完善视图

1. 重写更新(审批考勤)
   方法,原因是以视图集的形式调用序列化的update方法,DRF要求数据提交时,数据必须带上所有字段.可以查看源码`rest_framework_mixins.py`
   中的`UpdateModelMixin`:

```python
# ...
class UpdateModelMixin:
    """
    Update a model instance.
    """

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)  # 允许只传部分参数? 默认不允许!
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)
# ...
```

2. 重写列表(查看考勤列表)方法, 根据逻辑, 用户要么查看自己发起的考勤记录, 要么查看自己下属的考勤进行审批,
   并不能看见别人的或者不是本部门下级的考勤记录
3. 供发起考勤时,获取所有考勤类型的接口
4. 供发起考勤时,获取当前用户的审批者的接口

- 源代码`~/apps/absent/views.py`

```python
# ...

# 1. 重写更新方法
def update(self, request, *args, **kwargs):
    """
    重写update方法
    原因是:
    drf 要求 PUT 请求过来进行数据更新时,必须要把所有字段带上
    但是我们审核请假只需要改部分数据(考勤的状态1变2, 加上一个审批内容)
    """
    # 所以必须要声明kwargs['partial'] = True, 即允许只上传部分字段
    kwargs['partial'] = True
    # 调用父类的update方法更新数据
    return super().update(request, *args, **kwargs)


# 2. 重写列表方法
def list(self, request, *args, **kwargs):
    """
    重写list方法
    原因是:
    不是每个人都能获取所有的考勤信息,要么
    1, 个人获取个人的考勤信息
    2, 个人获取属下的考勤信息
    因此, 不带参数或者参数 who不等于sub的时候, 返回自己的考勤信息
    带参数 .../?who=sub的时候, 返回下属的考勤信息
    """
    queryset = self.get_queryset()
    # 获取地址里携带的参数 ../?who=???
    who = request.query_params.get('who')
    # 如果是 ../?who=sub
    if who and who == 'sub':
        # 那么获取审核者是当前用户的所有考勤信息
        result = queryset.filter(responder=request.user)
    else:
        # 否者获取发起者是当前用户的所有考勤信息
        result = queryset.filter(requester=request.user)

    # 这里序列化的数据是多条, 必须要声明many=True, 否则会报错
    serializer = self.serializer_class(result, many=True)

    # 返回给前端
    return response.Response(serializer.data)


# 3. 返回所有考勤类型的接口
class AbsentTypeView(APIView):
    """
    返回所有的请假类型
    """

    def get(self, request):
        types = AbsentType.objects.all()
        serializer = AbsentTypeSerializer(types, many=True)

        return response.Response(serializer.data)


# 4. 返回审批者的接口
class ResponderView(APIView):
    """
    返回当前登录用户发起考勤时, 他的审批者
    """

    def get(self, request):
        user = request.user
        responder = get_responder(user)
        serializer = UserSerializer(responder)

        return response.Response(serializer.data)
```

### 手动测试

1. 创建`~/apps/absent/management/commands/initabsenttypes.py`

```python
from django.core.management.base import BaseCommand
from apps.absent.models import AbsentType


class Command(BaseCommand):
    def handle(self, *args, **options):
        absent_list = ["事假", "病假", "工伤假", "婚假", "丧假", "产假", "探亲假", "公假", "年休假"]
        absents_types = []
        for name in absent_list:
            absents_types.append(AbsentType(name=name))

        # 批量创建 .bulk_create(由对象组成的数组,每个对象作为一条新记录)
        AbsentType.objects.bulk_create(absents_types)
        self.stdout.write('考勤类型数据初始化成功！')
```

2. 执行命令, 写入这些请假类型到数据库中
3. 用postman进行测试,包括
    - 发起考勤
    - 审核考勤
    - 从接口获取考勤类型
    - 从接口获取当前登录用户发起考勤后的审核人

> 到这里,我创建了`absent`考勤模块, 写好四个东西:1模型, 2序列化, 3视图, 4路由.在序列化和视图层, 我采用将重复代码抽离出来,
> 写在`utils.py`中的方法优化了代码, 采用重写父类写好的函数的形式完成了更复杂的逻辑. 最终完成了一套考勤模块的接口.
> 接下来改去完成前端了

### 完成分页

- 新建`~/apps/absent/paginations.py`, 做好分页配置,略
- 在视图层导入并且为视图集声明`pagination_class`
- 改写`list()`方法

```python
    def list(self, request, *args, **kwargs):


queryset = self.get_queryset()
who = request.query_params.get('who')
if who and who == 'sub':
    result = queryset.filter(responder=request.user)
else:
    result = queryset.filter(requester=request.user)

# 分页
page = self.paginate_queryset(result)
if page is not None:
    serializer = self.get_serializer(page, many=True)
    return self.get_paginated_response(serializer.data)

serializer = self.serializer_class(result, many=True)
return response.Response(serializer.data)
```

> 分页配置中, page_size 的值务必和前端一致.

# 通知模块

### 快速搭建api的工作流程

1. 新建app `python manage.py startapp inform`(记得`settings.py`里安装)
2. 新建模型,执行迁移(makemigration, migrate建表)
    - 模型文件知识点
    ```python
    class Meta:
        ordering = ('字段名称', ) # 依据哪个字段进行正序排序,倒序加负号-
        unique_together = ('inform', 'user') # 哪几个字段组合起来是唯一的
    ```
3. 配置序列化
    - 序列化文件知识点
   ```python
    # 前端只读: 其他序列化的数据拿过来嵌套, 交给前端时只可以读取
    # 前端只写: 前端传输数据到后端, 给本序列化创建数据时才用到(通常是外键id)
    # 当多对多关系时, 会有多个外键id, 所以还需要指定 many=True
    # 一旦指定外键id只写, 必须重写create方法(需要导入模型,重新用模型.objeacts进行外键模型和自己创建新数据)
    # 根据外键id查询多条数据 id__in=list
    departments = OADepartment.objects.filter(id__in=ids).all()
    ```
4. 配置视图集, 略
5. 注册路由
    - 导入`DefaultRouter`
    - 注册, 拼接
    - 在主路由中注册

### 断点调试

- 建好后端逻辑后, 用postman进行测试排错, 使用post 方法访问该视图集接口新建数据.
    - 当需要传入多条department_ids时, 不能写成一个列表, 而是写多个key为`department_ids`的input字段, 传过去自己会变成列表
    - 访问出现错误, 开始尝试断点调试(停止正常服务, 开启debug模式, 打上断点, 意味着程序执行到断点时停止,
      会显示当前内存空间里的变量究竟是什么样子, 点击下一步, 程序继续执行)
- 问题处理一:`ids`还是字符串,是因为调用了map后没有把值重新赋给ids,
  修改后的代码:`ids = list(map(lambda value: int(value), ids))`
    - 执行匿名函数, 传入参数value, 返回int(value), 即将传入的参数转为整数类型
    - map遍历可迭代对象, 接收两个参数(1是一个函数, 2是一个可迭代对象), 让可迭代对象里的每个值都去执行一次参数1传入的函数,
      返回值是一个新的可迭代对象
    - list将新的可迭代对象转为列表, 返回给ids
- 问题处理二: 报错发现`**validated_data`里面居然有`public`字段?
- 原来是模型里给该字段设置了默认值, 调用序列化后, 就把这个字段带进来了
    - 解决方法1, 不设置默认值
    - 解决方法2, 在序列化里声明该字段只读, 所以服务器传入数据->执行序列化后, 过来的对象还是没有public字段,
      public字段在下面的代码里再次赋值和保存
    ```python
    class Meta:
        model = Inform
        fields = "__all__"
        # 前端前端传过来并进行序列化时(也就是写入时),该字段不会被序列化
        read_only_fields = ('public',)
    ```
- 针对上面的问题再次捋一遍序列化的逻辑:
    - 读取数据: 前端发起GET请求, 视图集通过queryset的配置调用指定模型, 获取相关数据后再根据serializer_class
      对获取的数据进行序列化(转JSON), 这时候只写(write_only)就起作用了,它不会将声明为只写的字段添加进JSON串里
    - 写入数据: 前端发起POST/PUT请求, 视图集还是执行相同逻辑, 序列化这时候扮演两个角色: 1将表单数据转换成指定格式并执行验证
      2将表单数据写入数据库. 所以往往有外键的字段需要重写 create/update 方法,因为传过来的数据,比如 inform.departments
      它不只是一个由department.id 组成的列表, 而是department的全部信息, 所以前端我们要传过来的是department_ids,
      并且声明department只读不写, 这样前端过来的数据就只有department.id 组成的列表了

### 图片上传

> 前端已经建好了发布通知的页面, 集成了wangEditor富文本编辑器, 现在要实现wangEditor的图片上传功能

1. 新建app image
2. 创建序列化文件`serializers.py`, 该文件用于验证图片上传格式是否合规

```python
from rest_framework import serializers
from django.core.validators import FileExtensionValidator, get_available_image_extensions


class UploadImageSerializer(serializers.Serializer):
    image = serializers.ImageField(
        # 验证后缀名
        validators=[FileExtensionValidator(['png', 'jpg', 'jpeg', 'gif'])],
        # 配置提示信息
        error_messages={'required': '请上传图片！', 'invalid_image': '请上传正确格式的图片！'}
    )

    def validate_image(self, value):
        # 单位b, 1mb = 1024kb = 1024*1024b
        # 配置文件最大的大小
        max_size = 1 * 1024 * 1024
        # 获取当前文件的大小
        size = value.size
        # 如果当前文件的大小 大于 最大值
        if size > max_size:
            # 抛出异常
            raise serializers.ValidationError('图片最大不能超过1MB！')

        # 每个 validate_字段(self, value) 函数,都必须返回 value
        return value
```

3. 编辑视图`views.py`

```python
from rest_framework.views import APIView
from .serializers import UploadImageSerializer
from rest_framework.response import Response
from shortuuid import uuid  # 导入uuid进行文件重命名防攻击
import os  # 导入os包,等会要用里面的一个函数获取文件后缀名
from django.conf import settings  # 导入配置项, 需要里面关于MEDIA的配置项


class UploadImageView(APIView):
    def post(self, request):
        # 1, 验证数据
        serializer = UploadImageSerializer(data=request.data)
        if serializer.is_valid():
            # 2, 如果验证通过
            # 获取图片
            file = serializer.validated_data.get('image')
            # 配置名称
            filename = uuid() + os.path.splitext(file.name)[-1]
            # 配置存放地址
            path = settings.MEDIA_ROOT / filename
            try:
                # 打开文件
                with open(path, 'wb') as fp:
                    # 文件循环数据流(file.chunks())
                    for chunk in file.chunks():
                        # 写入数据流到path
                        fp.write(chunk)
            except Exception:
                # 写入过程中如果出现异常:
                return Response({
                    "errno": 1,
                    "message": "图片保存失败！"
                })
            # 如果没有出现异常
            return Response({
                "errno": 0,
                "data": {
                    "url": settings.MEDIA_URL + filename,
                    "alt": "图片",
                    "href": settings.MEDIA_URL + filename
                }
            })
        else:
            # 如果验证没有通过序列化的验证
            return Response({
                "errno": 1,
                "message": list(serializer.errors.values())[0][0]
            })
```

> 视图return回去的JSON, 是按照wangEditor要求的格式!成功返回`'errno':0` + `data`(data.url必须, 其余可选),
> 失败返回`'errno':1` + `message`

4. 编辑配置文件`settings.py`

```python
MEDIA_ROOT = BASE_DIR / 'media'
MEDIA_URL = "/media/"
```

> 在根目录下新建`~/media/`文件夹,用于存放上传的图片

5. 配置路由, 略
6. 用postman测试
    - POST请求配置的路由,填好header, 选`form-data`进行测试
    - key叫做image(serializer里配置的), type选`file`
   > 踩坑: 莫名其妙报错`PIL` module找不到, 也不知道哪里调用了, 总之, `pip install Pillow` 安装这个包即可

7. 报错:找不到PIL模块? `pip install Pillow`
8. 2个问题导致前端访问不到后端上传的图片
    - 图片地址没有路由, 在主路由加上
    ```python

    from django.conf.urls.static import static
    
    urlpatterns = [
    # 其他路由...
    # 后面拼接上这句话(static里面有提示):
    ] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    ```
    - 中间件拦住了
   ```python
    class LoginCheckMiddleware(MiddlewareMixin):
    keyword = 'JWT'
    def process_view(self, request, view_func, view_args, view_kwargs):
        # 加上条件, path以为`/media/`开头的, 也允许不经jwt校验访问
        if request.path == '/auth/login' or request.path.startswith(settings.MEDIA_URL):
            # 具体代码...
    ```

- **代码可复用,建议保存**

### 通知列表接口
> 视图集已经完成了通知列表功能, 但其自带的有以下两个问题: 1没有分页, 2返回的是全部的通知功能,没有进行任何筛选

1. 分页, 新建 `~/apps/inform/paginations.py`, 写好以后在视图层导入并在视图集声明`pagination_class = InformPagination`
2. 筛选, 通过重写 **get_queryset(self)**, `~/apps/inform/views.py` 中的 `InformViewSet` 视图集:
```python
    def get_queryset(self):
        """
        ModelViewSet 视图集默认返回所有数据
        虽然可以通过.objects.filter('筛选条件').all()进行简单筛选
        但当逻辑过于复杂, 且需要进行多表多次查询时, 应该考虑重写get_queryset方法, 来实现更复杂数据库查询的逻辑

        现在项目的需求是:
        1, 查询时, 查找到相关的通知发布者的信息(数据库里的外键存的只是author_id, 而不是用户的全部信息): select_related()
        2, 查询时, 通过多对多关系, 找到当前登录用户, 是否已读过本条通知: prefetch_related()
        3, 查询时, 需要遵循以下逻辑:
            3.1, 要么是公开的
            3.2, 要么可见部门里有当前登录用户的所属部门
            3.3, 要么通知的作者就是当前登录的用户
        4. 最后不能用all(), 而是 distinct() 避免数据重复

        这么做的原因是为了尽可能少地访问数据库
        """
        queryset = (self
                    # 减少访问数据库: 提前找到通知发布者
                    .queryset.select_related('author')
                    # 减少访问数据库: 提前找到通知是否已读的相关信息
                    .prefetch_related(Prefetch("been_read", queryset=InformRead.objects.filter(user_id=self.request.user.uid)), 'departments')
                    # 筛选出来: 1是公开的, 2是通知可见部门里有用户所属部门的, 3是通知发布者是用户自己的 所有数据
                    .filter(Q(public=True) | Q(departments=self.request.user.department) | Q(author=self.request.user))
                    # .distinct() 是从数据库中获取不重复的记录
                    .distinct())
        return queryset
```
### 通知详情接口
> 视图集已经帮我完成了这个详情页的接口, 但我需要更复杂的逻辑: 将阅读量交给前端
1. 实现阅读量的自动增加: 点击通知详情, 底层获取通知详情的同时也自动请求接口, 增加一条阅读量数据
   1. 接口在`~/apps/inform/views.py`中的`InformReadView`中
   2. 数据序列化在`ReadSerializer`中
   
   > 复习:想要针对某个字段进行更复杂的验证逻辑, `def validate_字段名(self, value):`, self是序列化自己, value就是被验证字段

   3. 记得配置路由
2. 想要在原始数据里面添加新的属性, 就需要重写视图集的`retrieve()`函数:
```python
def retrieve(self, request, *args, **kwargs):
    instance = self.get_object()
    serializer = self.get_serializer(instance)
    # 先用一个变量接收
    data = serializer.data
    # 再往里面拼属性
    data['been_read'] = InformRead.objects.filter(inform_id=instance.id).count()
    # 最后返回给前端
    return Response(data=data)
```

### 通知列表展示是否已读
1. 序列化嵌套, 新建`InformSerializer`模型序列化
2. 在`InformSerializer`新增字段`been_read`, 嵌套`InformReadSerializer` : `been_read = InformReadSerializer(many=True, read_only=True)`
3. 视图层重写`get_queryset()`时之前已经写好逻辑了, 略

> 名称冲突, 之前新增阅读量的序列化校验器改名为`ReadSerializer`, 阅读量模型序列化命名为`InformReadSerializer`

### 通知删除接口
> 视图集自带了删除方法, 但是逻辑不完善: 必须要判断通知的发布者(inform.author)是当前登录的用户(request.user), 所以必须重写`destroy()` 函数, 逻辑较为简单, 此处略.

# 员工管理模块

### 返回所有部门数据的接口

> 通知管理模块, 新建通知功能需要获取所有部门的数据, 其功能归属于staff模块

1. 命令新建app staff(记得`settings.py`安装)
2. 写好视图

```python
from rest_framework.generics import ListAPIView
from apps.oaauth.models import OADepartment
from apps.oaauth.serializers import DepartmentSerializer


# 直接继承 ListAPIView
class DepartmentListView(ListAPIView):
    queryset = OADepartment.objects.all()
    serializer_class = DepartmentSerializer
```

3. 注册路由

> 踩坑! 记住,只有视图集才需要导入DefaultRouter后实例化, 注册, 拼接进`urlpatterns`

- 像这种普通路由还是写在 urlpatterns 数组里
- 最后的路由地址是`staff/departmtents/`

### 新建员工
- 视图 `~apps/staff/views.py` 中新建 `StaffView` 接口, 继承`APIView`, 重写`post`方法
- 前端传来数据`realname, email, telphone`, 用序列化 `CreateStaffSerializer(serializers.Serializer)` 进行校验, 同时重写 `validate(self, attrs)`函数, 在函数内部进行判断, 确保1邮箱不重复, 2发起新建员工请求的用户是其所属部门的领导
- 配置路由
- 注意:踩的2个大坑: 
  - 1, 当视图接口**不是**模型视图集时候, 序列化类实例化后, 如果不这样传参数,`serializer = CreateStaffSerializer(data=request.POST, context={'request': request})`, 那么在序列化里, 是不能通过`self.context['request']`获取请求信息的
  - 2, 踩了两次了! js写多了喜欢打逗号!
  ```python
    # ...
    email = serializer.validated_data['email'], # 注意这个逗号, 它居然不会报错! 却会让 email 的数值类型变成元组!
    realname = serializer.validated_data['realname'], # 这个逗号让我排了好久的错!
    password = '111111'
    # ...
    ```
  > 错误提示原文的标题: `AttributeError: 'tuple' object has no attribute 'strip'`
### 发送激活邮件
> 新建员工成功后, 发送激活邮件

1. 采用 AES 加密被创建用户的邮箱
> 代码参考`~/utils/aeser.py`
> 
> 踩坑, 最新版本的`Crypto`包安装命令是: `pip3 install pycryptodome`, 而不是`pip install pycrypto`, 原因是后者并不安全且不再维护.
> 
> 还需要装`VSC++14.X`以上的版本
> 
> 一开始我装成了`pycrypto`, 又没有卸载直接装了 `pycryptodome`, 最后导致还是找不到包, 需要把两个都卸载了再安装
> 在遇到问题是,耐心使用AI工具进行排错
2. 发送邮件时,将被加密的邮箱作为token参数拼接在url中
3. 新接口`ActiveStaffView`的访问路由是`域名/staff/active/?token=第二步生成的token`
    - 记得配置路由
4. 新员工收到系统发送的邮件,点击链接,访问第三步生成的路由地址...

# Redis & Celery
### Redis
> Redis（Remote Dictionary Server）是一个开源的、高性能的 键值存储（Key-Value Store） 数据库，通常作为内存数据库使用。它广泛应用于缓存、会话存储、队列管理和实时数据处理等场景。
> 说人话: 存储在内存中的数据库(内存运行速度 > 硬盘)类似缓存, 又比一般缓存(memcached)要牛一点, 能够设置定时备份数据到硬盘里
 
> Redis官方没有提供Windows版本，也不推荐在Windows上使用。但是在开发阶段，我们还是有需求在windows上使用Redis的，这里讲解Redis 5版本在windows上安装教程，其他版本类似。

- 下载.msi:<a href="https://github.com/tporadowski/redis/releases">下载地址</a>
- 安装傻瓜式的:
  - 建议不要改路径, 同页**添加Redis到系统环境变量中**
  - 不要改端口, 同页**跨越windows防火墙**(防止无法使用)
  - 建议不要设置最大存储空间
  - 安装即可
- 基本命令
```
# 进入本机redis命令
redis-cli
# 进入其他服务器的redis(先要确认 redis安装路径下/redis.windows-service.conf 里面声明的 ip地址, 默认: bind 127.0.0.1)
redis-cli -h [ip] -p [端口]

# 创建键值对
set key value
# 根据键删除键值对
del key
# 根据键设置该键值对的过期时间, x秒后过期
expire key x
# 创建键值对的同时设置过期时间
setex key timeout x
# 查看过期时间
ttl key
# 查看redis里现在存储的所有key
keys *

# 列表新增元素: 如果key不存在,则会新建一个列表,并在列表最前面加入元素value
lpush key value
# 列表新增元素: 在列表最后面增加元素
rpush key value
# 查看列表这个区间的元素
lrange key start stop
# 删除列表同样
del key

# 集合操作:创建集合,以setName为名创建一个集合, 里面以下值(v1 v2)
sadd setName v1 v2
# 删除集合里面的值
srem setName v2
# 查看集合里面有几个元素
scard team1
# 求两个集合的交集
sinter set1 set2
# 求两个集合的并集
sunion set1 set2
# 获取多个集合的差集
sdiff set1 set2

# 哈希操作: 设置hash值
hset key field value
# 获取hash值(获取value)
hget key field
# 删除
hdel key field
# 获取某个hash_key里的全部field和value
hgetall key
# 获取field
hkeys key
# 获取全部key
hvals key
# 判断某个哈希里面是否有某个field
hexists key field
# 根据field获取键值对
hlen field

# 事务(开启后里面的命令要么全部正确执行, 如果有错, 则全部不执行并回滚数据到执行前)
# 开启事务
multi
# ... 编写你的命令后, exec正式执行
exec
# 取消, 回到multi前
discard
# 监视一个(或多个)key，如果在事务执行之前这个(或这些) key被其他命令所改动，那么事务将被打断。
watch key...
# 取消监听
unwatch

# 消息订阅功能 给某个频道发送消息
publish channel message
# 订阅某个频道
subscribe channel

# ...
```

### celery
- 应用场景:
  1. 大规模数据处理：Celery可以将一个大任务分解为多个小任务，这些小任务可以在多个工作者或服务器之间进行分发和处理。这使Celery特别适合大数据和机器学习等需要大规模并行处理的应用。
  2. 异步任务：Celery可以进行异步任务处理，例如发送邮件、推送通知、执行定期任务等，这些任务可以在未来的某个时间点执行，而不会阻塞主程序或应用程序。
  3. 定时任务：Celery还可以用于处理周期性任务，比如每天或每周定时执行的任务。这在许多web应用中都有广泛的应用，如数据分析、系统监控等
- 工作原理:在Celery中，主要有三个组件，分别是生产者（Producer）、消费者（Worker）和消息队列（Broker）。
  - 生产者：向消息队列发送任务的部分，通常是主应用程序（Django项目），比如我们的代码中生产了一个发送邮件的任务。
  - 消息队列：也被称为Broker，是一个在生产者和消费者之间传递消息的中介。当生产者发送一个任务时，这个任务将被放入消息队列中，等待消费者来取出并执行。一般使用Redis、RabbitMQ来作为消息队列。
  - 消费者：也就是我们通常所说的Worker，是从消息队列中取出任务并执行的部分。在Celery中，可以有多个Worker同时工作，每个Worker可以运行在不同的服务器或进程中，以实现任务的并行处理。
  > 脑部某些购物狂欢节: 客户下单买了商品, 其实商品还没进入系统后台订单中, 也没有立刻给经销商通知, 但是返回给客户的是已经购买成功, 其实这个购买的请求还在任务队列中, 等到前面的购买请求处理完了轮到这条请求时再处理:通知经销商, 生成真正的后台订单记录等等...(因为买东西的人太多了, 等到一个一个按顺序处理发起的购买请求, 客户得等到猴年马月, 所以客户下单直接告诉他你已经购买成功了)

- 安装: `pip install -U "celery[redis]"` (安装celery同时安装python操作redis的驱动程序)
- windows下想要启动celery 还需要安装 G_event: `pip install gevent`

### 正式投入使用:异步发送邮件
1. 在 `settings.py` 中配置好 celery
```python
# celery配置
# 中间人的配置
CELERY_BROKER_URL = 'redis://127.0.0.1:6379/1'
# 指定结果的接受地址(不能和上面一样, 所以地址为/2)
CELERY_RESULT_BACKEND = 'redis://127.0.0.1:6379/2'
# 指定任务序列化方式（默认是json），可选择有：json、yaml、pickle、msgpack
CELERY_TASK_SERIALIZER = 'json'
# 指定结果序列化方式（默认是json）
CELERY_RESULT_SERIALIZER = 'json'
```
2. 新建 `~/myoa_back/celery.py`, 代码可复用,建议保存
```python
import os
from celery import Celery
from celery.signals import after_setup_logger
import logging

# 设置django的settings模块，celery会读取这个模块中的配置信息
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myoa_back.settings')

app = Celery('myoa_back')

## 日志管理
@after_setup_logger.connect
def setup_loggers(logger, *args, **kwargs):
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # add filehandler
    fh = logging.FileHandler('logs.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

# 配置从settins.py中读取celery配置信息，所有Celery配置信息都要以CELERY_开头
app.config_from_object('django.conf:settings', namespace='CELERY')

# 自动发现任务，任务可以写在app/tasks.py中, 注意必须要确保app在settings.py中已经被安装
app.autodiscover_tasks()

# 测试任务
# bind=True, 在任务函数中, 第一个参数就是任务对象
# 如果bind=False, 或没有声明本参数, 那么任务函数中就没有该对象(下面的debug_task(self为空))
# ignore_result=True, 忽略任务执行结果
@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
```
3. 编辑 `~/myoa_back/__init__.py` 使项目启动时, 就启动celery
```python
# 导入当前目录下的 celery.app
from .celery import app as celery_app

# 类似于 js 的 export
__all__ = ('celery_app',)
```
4. 新建 `~/apps/staff/tasks.py`, 意为任务
```python
from myoa_back import celery_app
from django.core.mail import EmailMultiAlternatives
from django.conf import settings

# 定义了一个名叫 send_mail_task 的任务
@celery_app.task(name="send_mail_task")
# 这个任务执行 send_mail_task 函数, 接收3个参数: 邮箱地址, 真实姓名, 激活链接地址
def send_mail_task(email, realname, active_url):
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
                <br>
                <p>如果上方链接无法正确访问? 请自行复制和粘贴下方链接到浏览器地址栏中手动打开!</p>
                <p>{active_url}</p>
              </body>
            </html>
            """

    # 发送邮件
    email_sender = EmailMultiAlternatives(
        subject=subject,
        body="",
        from_email=from_email,
        to=[to_email],
    )
    email_sender.attach_alternative(html_content, "text/html")
    email_sender.send()
```
5. 修改 `~/apps/staff/views.py` 里的 `StaffView.send_active_email()` 方法, 这个函数只做两件事:
   - 拼好 active_url
   - 调用 tasks.py 里写好的异步任务函数: `send_mail_task.delay(email, realname, active_url)` (记得代码最上方导入)
6. 启动celery服务, 再次使用postman进行创建用户的测试 `celery -A myoa_back worker -l INFO -P gevent`
7. 测试后发现多了个 `logs.log` 文件, 用于记录celery执行的日志, 可以忽略追踪
8. 前端完成后再次测试, 发现视图层取不到前端传来的数据, 原来是代码写错了, DRF.APIView不再通过`request.POST`获取数据, 而是`serializer = CreateStaffSerializer(data=request.data, context={'request': request})`

### 员工激活
> 前面已经完成了: 部门直属领导有权新建员工, 通过创建时输入的邮箱给员工异步发送激活邮件, 现在处理是员工获得邮件后, 进行激活的工作

1. 改个小坑: 使用AES加密后的邮件, 会变成一串复杂的字符串, 但这个字符串存在编码问题, 比如`+`会被当成字符串拼接运算符, 所以修改代码
   - 导入parse(来自python自己的路由库urllib): `from urllib import parse`
   - 编码添加给路由添加参数:`?token=xxxxxxxxx`, 代码: `active_path = reverse("staff:active") + "?" + parse.urlencode({"token": token})`
2. 开始实现后台激活方法:
   - `GET`逻辑: 员工访问邮件所提供的链接, 也就是带AES加密token后的激活路由, 会访问到`ActiveStaffView`, 在这个视图的`GET`请求中, 使用django自带的DTL模板渲染一个激活页面(这么做是因为接下来要在服务器端操作cookie), 页面渲染完成前, 将token以cookie的形式存入浏览器中.
   - `POST`逻辑: 员工输入自己的邮箱, `POST`请求相同的路由, 接收表单传递的email, 比对cookie里的token解码后的email, 确认两者相等, 更新用户状态, 跳转到前端页面
```python
class ActiveStaffView(View):
    def get(self, request):
        # 获取地址里的token
        token = request.GET.get('token')
        
        # 创建response对象
        response = render(request, 'active.html')
        # 给对象存入cookie, key为token value为地址里token的值(AES加密后的用户邮箱)
        response.set_cookie('token', token)
        
        # 返回给前端渲染页面
        return response
    
    def post(self, request):
        # 获取cookie里的token
        token = request.COOKIES.get('token')
        # 如果没有, 禁止用户直接访问本页面
        if not token:
            return HttpResponseForbidden("缺少令牌，禁止访问")
        
        try:
            # 尝试解码token, 还原为用户的email
            email = aes.decrypt(token)
            # 比对用户输入的email 和 解码后的email, 如果不相等
            if email != request.POST.get('email'):
                # 返回403
                return HttpResponseForbidden("无效令牌，禁止访问")
            
            # 两者相等后, 再从数据库获取user
            user = OAUser.objects.get(email=email)
            # 必须是"未激活"的用户才可以被激活, "被锁定", "已激活"的禁止访问
            if user.status != UserStatusChoices.UNACTIVED:
                return HttpResponseForbidden("用户状态无效，禁止访问")

            # 更新用户状态并保存
            user.status = UserStatusChoices.ACTIVED
            user.save()
            # 重定向到前端并且添加路由参数 from=back
            return HttpResponseRedirect(str(settings.FRONTEND_URL + "/login/?from=back"))
        
        # 当try的过程中出现其他错误时:
        except:
            return HttpResponseForbidden("系统错误，请联系管理员")
```
3. 视图静态页面`~/templates/active.html`, 交给ai
4. 处理中间件(整个白名单吧, 现在登录接口, 激活页面, wangEditor上传的图片都不需要登录认证): `if request.path.startswith(settings.MEDIA_URL) or request.path in WhiteList.path: #设置匿名用户, 跳过中间件 return None`
5. 规范编码, 编辑`settings.py`, 配置前端域名`settings.FRONTEND_URL`: `FRONTEND_URL = "http://localhost:5173/#"`

### 员工列表
> 细想之下, 关于员工的视图, 我有新增, 修改(状态), 列表三个功能需要实现, 所以不如直接把这个视图接口改造成视图集
- 源代码
```python
# 通过继承, 删减掉删除(mixins.DestroyModelMixin)功能
class StaffViewSet(mixins.CreateModelMixin, 
                mixins.UpdateModelMixin,
                mixins.ListModelMixin,
                viewsets.GenericViewSet):
    
    # 配置模型
    queryset = OAUser.objects.all()
    
    # 配置序列化类: 重点,本视图集涉及两个序列化类: 
    # 1, 新增员工时, 是CreateStaffSerializer序列化验证器
    # 2, 查询列表时, 是apps.oaauth.serializers.Userserializer类
    def get_serializer_class(self):
        if self.request.method == 'GET':
            return UserSerializer
        else:
            return CreateStaffSerializer
    
    # 3, 配置分页: 当前目录下的 paginations.UserPagination, 略
    pagination_class = UserPagination
    
    # 这个是发送邮件的函数, 略
    def send_active_email(self, email, realname):
        # 处理 AES 加密
        token = aes.encrypt(email)
        active_path = reverse("staff:active") + "?" + parse.urlencode({"token": token})
        active_url = self.request.build_absolute_uri(active_path)

        # 异步发送邮件
        send_mail_task.delay(email, realname, active_url)
    
    # 新增员工: 重写 mixins.CreateModelMixin.craete()
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
    
    # 通过配置 get_queryset() 实现员工列表筛选
    def get_queryset(self):
        queryset = self.queryset
        user = self.request.user
        
        # 如果不是董事会的
        if user.department.name != '董事会':
            # 也不是本部门的领导
            if user.uid != user.department.leader.uid:
                # 那就报错(只有部门领导和董事会成员可以查看员工列表)
                raise exceptions.PermissionDenied()
            else:
                # 是部门领导, 则仅返回本部的员工列表
                queryset = queryset.filter(department_id=user.department_id)
                
        
        # 以加入时间倒序排序
        return queryset.order_by("-date_joined").all()
```
- **视图集路由都必须注册**, 其他路由加上`staff/`
- 总路由删除前面的`staff`

### 员工锁定
1. 实现逻辑:重写`StaffViewSet.update()`方法, 原方法调用 UserSerializer 的 update 方法, 实现状态修改
2. 解析原`mixins.UpdateModelMixin.update`:
```python
class UpdateModelMixin:
    """
    Update a model instance.
    """
    def update(self, request, *args, **kwargs):
        # 是否允许传入部分参数而非整个对象进行修改, 默认不允许
        partial = kwargs.pop('partial', False)
        # 获取修改的模型
        instance = self.get_object()
        # 获取指定的序列化
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        # 如果验证通过
        serializer.is_valid(raise_exception=True)
        # 调用下面的函数存储数据
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    def perform_update(self, serializer):
        # 序列化对象.存储() => 保存数据到数据库中
        serializer.save()
```
3. 所以我们重写需要: 1, 指定正确的序列化; 2,允许传入部分参数(只传状态), `~/apps/staff/views.py中`
```python
def get_serializer_class(self):
    # 如果是 GET, PUT 两种请求方式, 那么使用 UserSerializer 序列化类
    if self.request.method in ['GET', 'PUT']:
        return UserSerializer
    # 否则就是POST新增员工, 使用 CreateStaffSerializer 序列化类
    else:
        return CreateStaffSerializer

# ...

def update(self, request, *args, **kwargs):
    kwargs['partial'] = True # 允许传入部分参数(给关键字参数配置一个新的,key为partial, 值为True的字段)
    return super().update(request, *args, **kwargs) #调用父类的update方法,传入kwargs
```
4. 去前端实现PUT请求本接口: `.../staff/<staff.uid>`, 传入数据`{status: 3}`

### 员工列表筛选
> 根据部门, 真实姓名, 加入时间进行筛选

- 重写 `~/apps/staff/views.py`的 `StaffViewSet.get_queryset()`实现
```python
    def get_queryset(self):
        # 获取初始的queryset
        queryset = self.queryset
        # 获取request信息
        request = self.request
        # 获取传入的部门id: request.query_params.get('key')
        department_id = int(request.query_params.get('department_id'))
        # 获取传入的真实姓名
        realname = str(request.query_params.get('realname'))
        # 获取传入的时间, 是一个数组: key[] = v1 & key[] = v2, 所以要用 .getlist('key[]') 获取
        date_range = request.query_params.getlist('date_range[]')
        
        # 董事会筛选
        if request.user.department.name != '董事会':
            # 判断是否是非董事会的部门领导
            if request.user.uid != request.user.department.leader.uid:
                raise exceptions.PermissionDenied()
            else:
                queryset = queryset.filter(department_id=request.user.department_id)
        else:   
            # 进行真名筛选
            if realname != '':
                queryset = queryset.filter(realname=request.query_params.get('realname'))
        
        # 进行部门筛选
        if department_id > 0:
            queryset = queryset.filter(department_id=department_id)
        
        # 进行时间筛选
        if date_range:
            try:
                # 调用 python.datetime.datime.strptime() 删除, 将参数1传入的时间变为参数2指定的格式, 返回值是一个python.datetime对象
                start_date = datetime.strptime(date_range[0], "%Y-%m-%d")
                end_date = datetime.strptime(date_range[1], "%Y-%m-%d")
                # 查询 date_joined__range=(起始时间, 结束时间)
                # 相当于 "SELECT...WHERE date_joined BETWEEN 起始时间 AND 结束时间"
                queryset = queryset.filter(date_joined__range=(start_date, end_date))
            except Exception:
                # 如果出现异常, 不做任何操作, 正常查询(防止传入时间超过当前时间)
                pass

        return queryset.order_by("-date_joined").all()
```
- 重点
  - 获取url参数(?key=xxx): `self.request.query_params.get('key')`
  - 获取url列表形式的参数(?key[]=x&key[]=y): `self.request.query_params.get('key[]')`
  - 查询筛选一个时间段: `.filter(字段名__range=(起始范围, 结束范围))`, 对应SQL语言: `...WHERE 字段名 BETWEEN 起始 AND 结束`

### 员工列表下载
> 后端处理: 前端选中员工, 点击下载(传入参数), 根据参数获取数据, 然后处理成Excel文件, 把Excel带进响应对象里, 交给前端
- 首先需要借用 `pandas` 包: `pip install pandas`
- 同时有个坑, 就是需要下载另外一个包才能把数据写进响应里: `pip install pandas openpyxl`
- 源代码
```python
# 引入pands包, 别名pd
import pandas as pd

class StaffDownloadView(APIView):
    def get(self, request):
        # 获取员工数据(未筛选前)
        queryset = OAUser.objects.all()
        # 获取传入的id, 要求传入的格式是 ids=[uid, uid, uid]
        ids = request.query_params.get('ids')

        try:
            # 这时候是 '[]' 不是 [], 是个两头带中括号的字符串不是列表, 转成列表
            ids = json.loads(ids)
        except:
            return Response(data={'detail': '员工参数错误!'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # 执行判断, 既不隶属于董事会, 又不是本部门的领导
            if request.user.department.name != '董事会':
                if request.user.uid != request.user.department.leader.uid:
                    # 那就报错
                    raise exceptions.PermissionDenied()
                else:
                    # 如果仅不是董事会的, 就进行初步筛选: 本部领导可以读取所属部门的职员的信息
                    queryset = queryset.filter(department_id=request.user.department.id)
            
            # 进一步筛选: 筛选出pk, 即uid在 ids里的数据
            queryset = queryset.filter(pk__in=ids)
            
            # 处理数据: 只需要这些字段:
            result = queryset.values("realname", "email", "telphone", "department__name", "date_joined", "status")
            
            # 重点:调用 pandas 包的 数据流函数, 将结果转为数据流
            staff_df = pd.DataFrame(list(result)) # 这里list(result)会直接强制让queryset生效并转为列表(一般queryset要return 出去的时候才会真正访问数据库)
            # 处理status , 123转对应中文
            status_mapping = {1: "已激活", 2: "待激活", 3: "已锁定"}
            staff_df["status"] = staff_df["status"].map(status_mapping)
            
            # 重命名列头
            staff_df = staff_df.rename(columns={
                "realname": "真实姓名",
                "email": "电子邮箱",
                "telphone": "联系电话",
                "department__name": "所属部门",
                "date_joined": "入职时间",
                "status": "当前状态"
            })
            
            # 创建response对象, 指定内容类型为 xlsx
            response = HttpResponse(content_type='application/xlsx')
            # 配置响应信息, 是附件attachment形式
            # (普通是inline形式, 也就是告诉浏览器响应是需要被你渲染的, 而attachment是附件是需要你浏览器进行下载的)
            # filename是指定下载文件的名称
            response['content-Disposition'] = "attachment; filename=员工信息.xlsx"
            
            # 写入数据到响应中
            with pd.ExcelWriter(response) as writer:
                staff_df.to_excel(writer, sheet_name='员工信息')
                
            # 返回响应
            return response
        except Exception as e:
            return Response(data={'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
```
- 配置路由, 略
- 代码可复用, 保存

### 上传员工信息
> 创建一个被POST请求的接口, 上传写有员工信息的Excel文件, 先判断登录的用户是否有权创建, 然后进行序列化(校验数据顺便转成序列化对象), 将序列化后的对象用 pandas.read_excel函数读取并遍历写入空列表中, 写入同时判断是否有权创建, 邮箱是否重复, 最后将这个列表作为批量数据, 用OAuser模型批量创建新数据

- 视图层源代码
```python
class StaffUploadView(APIView):
    def post(self, request):
        # 权限检查: 如果不是董事会的, 也不是部门的领导
        if request.user.department.name != '董事会' and request.user.uid != request.user.department.leader.uid:
            # 那就报错: 不允许上传
            return Response({'detail': '无权进行此操作'}, status=status.HTTP_403_FORBIDDEN)

        # 序列化器(导入./serializers.StaffUploadSerializer)验证
        serializer = StaffUploadSerializer(data=request.data)
        if not serializer.is_valid():
            # 如果没通过验证, 报错
            detail = list(serializer.errors.values())[0][0]
            return Response({'detail': detail}, status=status.HTTP_400_BAD_REQUEST)

        # 读取上传的Excel文件
        file = serializer.validated_data['file']
        # 配置需要的列的格式
        required_columns = ['所属部门', '真实姓名', '电子邮箱', '联系电话']

        try:
            # 使用 pandas.read_excel() 函数读取文件
            staff_data = pd.read_excel(file)
            # 检查必要列是否存在
            if not all(col in staff_data.columns for col in required_columns):
                missing = [col for col in required_columns if col not in staff_data.columns]
                return Response({'detail': f"缺少必要的列: {', '.join(missing)}"}, status=status.HTTP_400_BAD_REQUEST)
            
            # 空列表: 用于等会批量往数据库写入信息
            users = []
            # 遍历Excel行数据
            for index, row in staff_data.iterrows():
                # 获取部门并验证
                department_name = row['所属部门']
                department = OADepartment.objects.filter(name=department_name).first()
                # 如果部门不存在
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
                # 配置初始密码
                user.set_password('111111')
                # 添加到空列表中
                users.append(user)
                # ... 一致循环遍历Excel所有行

            # 使用事务批量创建用户
            with transaction.atomic():
                OAUser.objects.bulk_create(users)

            # 遍历发送激活邮件
            for user in users:
                send_active_email(request, user.email, user.realname)
            
            # 计算创建的总数
            count = len(users)
            return Response({'detail': f'共{count}条员工信息创建成功!'}, status=status.HTTP_201_CREATED)
        
        # 当 pandas 读入文件为空时
        except pd.errors.EmptyDataError:
            return Response({'detail': 'Excel文件为空'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'detail': f'发生错误: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
```
- 序列化器非常简单, 参考图片上传功能, 使用`FileExtensionValidator`类对上传文件进行验证即可
- 记得配置路由

### 补充: 修改部门信息
> 课程外内容: 部门信息可以被修改, 包括名称name, 简介intro, 直属领导leader, 分管董事manager

1. 新增视图接口`DepartmentUpdateView(UpdateAPIView)`, 继承自UpdateAPIView, 这个函数指定了queryset和serializer_class后, 会调取指定模型, 根据传入的主键id实例化指定对象, 再调用序列化器里的update函数
2. 配置序列化器, 并配置update函数
```python
class DepartmentUpdateSerializer(serializers.Serializer):
    # 指定字段
    id = serializers.IntegerField()
    name = serializers.CharField(required=True)
    intro = serializers.CharField(required=True)
    leader = serializers.CharField(required=True)
    manager = serializers.CharField(allow_null=True)
    
    # 必须自己写update, 1是因为继承的不是ModelSerializer, 2是我还有自己的逻辑
    def update(self, instance, validated_data):
        # 获取请求者
        request = self.context['request']
        user = request.user
        
        # 如果请求者不是超级用户(老板)
        if user.is_superuser != 1:
            # 不能改
            raise exceptions.APIException(detail='只有老板可以修改部门信息!')
        
        # 修改名称,简介
        instance.name = validated_data['name']
        instance.intro = validated_data['intro']
        
        # 获取leader信息
        leader = OAUser.objects.get(uid=validated_data['leader'])
        # 进行判断: 如果leader所属的部门, 不是当前要被修改信息的部门
        if leader.department.id != instance.id:
            # 那么报错
            raise exceptions.APIException(detail='只能任命隶属本部的成员作为部门领导!如需抽调任职,请先修改员工所属部门为当前部门!')
        else:
            # 否则修改leader
            instance.leader = leader
        
        # 如果有传入manager
        if validated_data['manager']:
            instance.manager = OAUser.objects.get(uid=validated_data['manager'])
        
        # 保存
        instance.save()
        
        # return出去
        return instance
```
3. 针对仅提供修改(PUT请求可访问)的接口, 需要自己配置路由
```python
urlpatterns = [
    path('departmetns/<pk>/', views.DepartmentUpdateView.as_view(), name="updatedepartment")
] + router.urls
```
4. 前端编辑部门时, 还需要获取员工信息
```python
class StaffListView(ListAPIView):
    """
    返回不分页的员工列表
    """
    queryset = OAUser.objects.order_by("date_joined").all()
    serializer_class = UserSerializer
```
5. 同样需要配路由, 略

### 在开发过程中遇到的一个大坑
> 最先开始, 想采用序列化嵌套的方式, 获取部门时直接获取其leader的信息, 结果打开`~/apps/serializer.py`才发现: 为了让用户获取其所属部门的信息, 我把部门的序列化写在前面, 而写在前面的部门序列化器, 是不能指定User序列化器作为其自身的嵌套的(除非UserSerializer写在前面),这样就导致了**循环依赖**: A依赖B, B也依赖A. 我至今没有找到方法解决!

> 所以只有在部门列表页面一次性把全部的user拉出来, 在前端进行筛选, 在修改时也同样, 我需要再用 `leader = OAUser.objects.get(uid=validated_data['leader'])` 获取被选择的直属领导进行修改, 如果有manager还得再请求一次数据库, 这样非常浪费数据库资源, 还好我设置为只有老板可以修改数据.

# 首页展示接口
### 三个接口
1. 展示最新10条通知信息, 注意数据筛选部分(.filter)
2. 展示最新10条请假信息, 同样注意数据筛选部分(.filter)
3. 展示部门员工和数量, 注意新增虚拟字段和展示字段部分(.annotate, .value)
4. 使用redis进行页面缓存(settings.py里配置好后给函数加装饰器)
- 源代码 `~apps/home/views.py`
```python
from rest_framework.views import APIView
from rest_framework.response import Response

# 通知
from apps.inform.models import Inform, InformRead
from apps.inform.serializers import InformSerializer

# 考勤
from apps.absent.models import Absent,AbsentStatusChoices
from apps.absent.serializers import AbsentSerializer
from django.db.models import Q,Prefetch

# 部门人员总数
from apps.oaauth.models import OADepartment
from django.db.models import Count

# 缓存用的装饰器
from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator


class LatestInformView(APIView):
    """
    返回最新10条通知
    """
    
    # 通过 method_decorator()装饰器加载另一个装饰器cache_page(), 因为我们是类视图, 必须这样加载
    @method_decorator(
        # 还得注意一点: 为了区分请求用户的所属部门, 还需要指定key_prefix(键前缀)参数
        # 这个参数的值就是一个字符串: dept_请求的用户的部门的id
        # lambda 匿名函数格式 lambda 参数:运算结果无需return
        # 这玩意儿也就等于 def 匿名 (req) : return "dept" + str(req.user.department.id)
        cache_page(60 * 15, key_prefix=lambda req: f"dept_{req.user.department.id}")
    )
    def get(self, request):
        
        # 进行数据筛选
        informs = (
            Inform.objects
            # 预查询
            .prefetch_related(
                # 预查询当前通知于当前请求用户是否已已读
                Prefetch('been_read', queryset=InformRead.objects.filter(user_id=request.user.uid)),
                # 预查询通知可见部门
                'departments'
            )
            # 筛选
            .filter(
                # 要么公开
                Q(public=True) |
                # 要么所属部门的列表里有当前用户所属部门(即该用户所属部门可见的非公开的通知)
                Q(departments__id=request.user.department.id)
            )
            # distinct去重 [:10]取最新10条
            # 因为模型里面 ordering 配置好了规则以 create_time 倒序排序所以这里不需要再 .order_by() 了
            .distinct()[:10]
        )
        
        # 进行序列化(转json, 告诉序列化器这是多条数据而非一条 many=True)
        serializer = InformSerializer(informs, many=True)
        
        # 返回drf响应, 实现接口获得请求 -> 处理好数据筛选 -> 往外抛出数据
        return Response(serializer.data)


class LatestAbsentView(APIView):
    @method_decorator(
        cache_page(60 * 15, key_prefix=lambda req: f"dept_{req.user.department.id}")
    )
    def get(self, request):
        # 这次换一个写法
        queryset = Absent.objects
        
        # 如果请求的用户不是董事会的
        if request.user.department.name != '董事会':
            # 那么该用户只能看得见
            queryset = queryset.filter(requester__department=request.user.department).order_by('-create_time')[:10]
        else:
            # 获取10条待审核的请假信息
            queryset = queryset.filter(status=AbsentStatusChoices.REVIEW).order_by('-create_time')[:10]
        
        # 序列化
        serializer = AbsentSerializer(queryset, many=True)
        
        # 返回给前端
        return Response(serializer.data)


class DepartmentStaffCount(APIView):
    @method_decorator(cache_page(60 * 15))
    def get(self, request):
        # 通过模型.objects.annotate(虚拟字段=值)给查询对象新增一个虚拟字段
        # Count计算外键数量作为staff_count字段的值(department_staffs定义在OAUser模型的字段department里的related_name中)
        # .values(字段1,字段2), 保留需要的字段
        datas =OADepartment.objects.annotate(staff_count=Count('department_staffs')).values("name", "staff_count")
        
        # 直接返回
        return Response(datas)
```
- 别忘了路由, 略