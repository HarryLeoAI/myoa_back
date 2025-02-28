from rest_framework import serializers,exceptions
from django.contrib.auth import get_user_model
from django.core.validators import FileExtensionValidator

OAUser = get_user_model()
class CreateStaffSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    realname = serializers.CharField(min_length=2, max_length=10, error_messages={
        'min_length': '真名不得少于2个字',
        'max_length': '真名不得多于10个字'
    })
    telphone = serializers.IntegerField()

    def validate(self, attrs):
        request = self.context['request']
        # 验证邮箱是否存在
        if OAUser.objects.filter(email = attrs.get('email')).exists():
            raise serializers.ValidationError('邮箱已被注册!')

        if request.user.department.leader_id != request.user.uid:
            raise serializers.ValidationError('仅部门直属领导添加员工!')

        return attrs

class StaffUploadSerializer(serializers.Serializer):
    file = serializers.FileField(
        validators=[FileExtensionValidator(['xlsx', 'xls'])],
        error_messages={'required': '请上传Excel文件！'}
    )

class DepartmentUpdateSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    name = serializers.CharField(required=True)
    intro = serializers.CharField(required=True)
    leader = serializers.CharField(required=True)
    manager = serializers.CharField(allow_null=True)

    def update(self, instance, validated_data):
        request = self.context['request']
        user = request.user

        if user.is_superuser != 1:
            raise exceptions.APIException(detail='只有老板可以修改部门信息!')

        instance.name = validated_data['name']
        instance.intro = validated_data['intro']

        leader = OAUser.objects.get(uid=validated_data['leader'])
        if leader.department.id != instance.id:
            raise exceptions.APIException(detail='只能任命隶属本部的成员作为部门领导!如需抽调任职,请先修改员工所属部门为当前部门!')
        else:
            instance.leader = leader

        if validated_data['manager']:
            instance.manager = OAUser.objects.get(uid=validated_data['manager'])

        instance.save()

        return instance