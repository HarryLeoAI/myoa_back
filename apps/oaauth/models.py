from django.db import models
from django.contrib.auth.models import User, AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.contrib.auth.hashers import make_password
from shortuuidfield import ShortUUIDField


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
    uid = ShortUUIDField(primary_key=True) # 主键:uid
    realname = models.CharField(max_length=8, unique=False)  # 真名
    email = models.EmailField(unique=True, blank=False)  # 邮箱
    telphone = models.CharField(max_length=20, blank=True)  # 电话
    is_staff = models.BooleanField(default=True)  # django自带, 是否是员工, 默认为是
    is_active = models.BooleanField(default=True)  # django自带, 是否激活, 默认为是
    status = models.IntegerField(choices=UserStatusChoices, default=UserStatusChoices.UNACTIVED)  # 用户状态,默认为未激活
    date_joined = models.DateTimeField(auto_now_add=True)  # 新增时自动添加当前时间

    department = models.ForeignKey('OADepartment', null=True, on_delete=models.SET_NULL, related_name='department_staffs', related_query_name='department_staffs')

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

class OADepartment(models.Model):
    """
    部门表
    """
    name = models.CharField(max_length=64) # 部门名称
    intro = models.CharField(max_length=256) # 部门简介
    leader = models.OneToOneField(OAUser, on_delete=models.SET_NULL, null=True, related_name='leader_department', related_query_name='leader_department')
    manager = models.ForeignKey(OAUser, on_delete=models.SET_NULL, null=True, related_name='manager_departments', related_query_name='manager_departments')
