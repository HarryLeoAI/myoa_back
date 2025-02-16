from rest_framework import serializers,exceptions
from .models import Absent, AbsentType, AbsentStatusChoices
from apps.oaauth.serializers import UserSerializer
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

    def validate_absent_type_id(self, value):
        if not AbsentType.objects.filter(pk=value).exists():
            raise exceptions.ValidationError("考勤类型不存在！")
        return value

    class Meta:
        model = Absent
        fields = "__all__"

    def create(self, validated_data):
        """发起请假"""
        # 获取request请求信息, 我需要里面的user
        request = self.context['request']
        # 请假发起者
        user = request.user
        # 审批者
        responder = get_responder(user)

        # 状态
        if responder is None:
            validated_data['status'] = AbsentStatusChoices.AGREED
        else:
            validated_data['status'] = AbsentStatusChoices.REVIEW

        # 写入数据库
        return Absent.objects.create(**validated_data, requester=user, responder=responder)

    def update(self, instance, validated_data):
        """审批请假"""
        request = self.context['request']
        user = request.user

        if instance.status != AbsentStatusChoices.REVIEW:
            raise exceptions.APIException(detail='禁止修改!')

        if instance.responder.uid != user.uid:
            raise exceptions.AuthenticationFailed(detail='没有权限!')

        instance.status = validated_data['status']
        instance.response_content = validated_data['response_content']
        instance.save()

        return instance