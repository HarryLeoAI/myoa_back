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

class RestPasswordSerializer(serializers.Serializer):
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
class RestPasswordView(APIView):
    """
    重置密码
    """
    def post(self, request):
        # 先序列化, 这里context属性, 是用于传入自定义数据的, 要求以字典(键值对)的格式
        serializer = RestPasswordSerializer(data=request.data, context={'request': request})
        # 如果数据验证成功
        if serializer.is_valid():
            # 获取密码
            password = serializer.validated_data.get('new_password')
            # 修改密码
            request.user.set_password(password)
            # 保存修改
            request.user.save()
            return Response({'message': '密码修改成功'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail':list(serializer.errors.values())[0][0]}, status=status.HTTP_400_BAD_REQUEST)
```