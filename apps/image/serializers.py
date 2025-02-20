from rest_framework import serializers
from django.core.validators import FileExtensionValidator


class UploadImageSerializer(serializers.Serializer):
    image = serializers.ImageField(
        validators=[FileExtensionValidator(['png', 'jpg', 'jpeg', 'gif'])],
        error_messages={'required': '请上传图片！', 'invalid_image': '请上传正确格式的图片！'}
    )

    def validate_image(self, value):
        # 单位b, 1mb = 1024kb = 1024*1024b
        max_size = 1 * 1024 * 1024
        size = value.size
        if size > max_size:
            raise serializers.ValidationError('图片最大不能超过1MB！')
        return value
