from rest_framework import serializers, exceptions
from .models import Inform, InformRead
from apps.oaauth.serializers import UserSerializer, DepartmentSerializer
from apps.oaauth.models import OADepartment


class InformReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = InformRead
        fields = "__all__"


class InformSerializer(serializers.ModelSerializer):
    author = UserSerializer(read_only=True)
    departments = DepartmentSerializer(many=True, read_only=True)

    # ids
    department_ids = serializers.ListField(write_only=True)
    # reads
    been_read = InformReadSerializer(many=True, read_only=True)

    class Meta:
        model = Inform
        fields = "__all__"
        read_only_fields = ('public',)

    def create(self, validated_data):
        ids = validated_data.pop('department_ids')
        ids = list(map(lambda value: int(value), ids))

        if len(ids) == 0:
            raise exceptions.ValidationError('必须选择可见部门!')

        if 0 in ids:
            newInform = Inform.objects.create(public=True, author=self.context['request'].user, **validated_data)
        else:
            departments = OADepartment.objects.filter(id__in=ids).all()
            newInform = Inform.objects.create(public=False, author=self.context['request'].user, **validated_data)
            newInform.departments.set(departments)
            newInform.save()

        return newInform


class ReadSerializer(serializers.Serializer):
    inform_id = serializers.IntegerField()

    def validate_inform_id(self, value):
        if not Inform.objects.filter(pk=value).exists():
            raise exceptions.ValidationError("这条通知不存在！")
        return value
