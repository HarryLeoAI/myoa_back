from rest_framework import viewsets, mixins, response
from .models import Absent, AbsentType, AbsentStatusChoices
from .serializers import AbsentSerializer, AbsentTypeSerializer
from rest_framework.views import APIView
from .utils import get_responder
from apps.oaauth.serializers import UserSerializer


class AbsentViewSet(mixins.CreateModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    mixins.ListModelMixin,
                    viewsets.GenericViewSet):
    """
    请假功能视图集
    """
    queryset = Absent.objects.all()
    serializer_class = AbsentSerializer

    def update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return super().update(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        who = request.query_params.get('who')
        if who and who == 'sub':
            result = queryset.filter(responder = request.user)
        else:
            result = queryset.filter(requester = request.user)

        serializer = self.serializer_class(result, many=True)

        return response.Response(serializer.data)

class AbsentTypeView(APIView):
    """
    返回所有的请假类型
    """
    def get(self, request):
        types = AbsentType.objects.all()
        serializer = AbsentTypeSerializer(types, many=True)

        return response.Response(serializer.data)

class ResponderView(APIView):
    """
    返回当前登录用户发起考勤时, 他的审批者
    """
    def get(self, request):
        user = request.user
        responder = get_responder(user)
        serializer = UserSerializer(responder)

        return response.Response(serializer.data)
