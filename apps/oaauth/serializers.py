from rest_framework import serializers
from .models import OAUser, UserStatusChoices, OADepartment


class LoginSerializer(serializers.Serializer):
    """
    登录序列化
    """
    email = serializers.EmailField(required=True)  # 邮箱:必填
    password = serializers.CharField(max_length=32, min_length=6)  # 密码

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = OAUser.objects.filter(email=email).first()
            if not user:
                raise serializers.ValidationError('请输入正确的邮箱!')
            if not user.check_password(password):
                raise serializers.ValidationError('请输入正确的密码!')
            if user.status == UserStatusChoices.UNACTIVED:
                raise serializers.ValidationError('用户尚未激活,请联系管理员!')
            if user.status == UserStatusChoices.LOCKED:
                raise serializers.ValidationError('用户已被锁定,请联系管理员!')

            attrs['user'] = user
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
    department = DepartmentSerializer()  # 部门详情

    class Meta:
        model = OAUser
        exclude = ['password', 'groups', 'user_permissions']
