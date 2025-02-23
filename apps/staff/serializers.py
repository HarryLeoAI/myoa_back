from rest_framework import serializers
from django.contrib.auth import get_user_model

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