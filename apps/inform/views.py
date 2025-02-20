from rest_framework import viewsets
from .models import Inform
from .serializers import InformSerializer

class InformViewSet(viewsets.ModelViewSet):
    queryset = Inform.objects.all()
    serializer_class = InformSerializer