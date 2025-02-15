from rest_framework import serializers, exceptions
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

        user = self.context['request'].user
        if not user.check_password(old_password):
            raise exceptions.ValidationError('旧密码错误!')

        return attrs
