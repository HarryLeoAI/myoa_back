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
