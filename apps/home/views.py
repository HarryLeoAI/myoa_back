from django.db.models import Q,Prefetch
from rest_framework.views import APIView
from rest_framework.response import Response

from apps.inform.models import Inform, InformRead
from apps.inform.serializers import InformSerializer

from apps.absent.models import Absent,AbsentStatusChoices
from apps.absent.serializers import AbsentSerializer

from apps.oaauth.models import OADepartment
from django.db.models import Count

from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator


class LatestInformView(APIView):

    @method_decorator(
        cache_page(60 * 15, key_prefix=lambda req: f"dept_{req.user.department.id}")
    )
    def get(self, request):

        informs = (
            Inform.objects
            .prefetch_related(
                Prefetch('been_read', queryset=InformRead.objects.filter(user_id=request.user.uid)),
                'departments'
            )
            .filter(
                Q(public=True) |
                Q(departments__id=request.user.department.id)
            )
            .distinct()[:10]
        )
        serializer = InformSerializer(informs, many=True)
        return Response(serializer.data)


class LatestAbsentView(APIView):
    @method_decorator(
        cache_page(60 * 15, key_prefix=lambda req: f"dept_{req.user.department.id}")
    )
    def get(self, request):
        queryset = Absent.objects

        if request.user.department.name != '董事会':
            queryset = queryset.filter(requester__department=request.user.department).order_by('-create_time')[:10]
        else:
            # 获取10条待审核的请假信息
            queryset = queryset.filter(status=AbsentStatusChoices.REVIEW).order_by('-create_time')[:10]

        serializer = AbsentSerializer(queryset, many=True)

        return Response(serializer.data)


class DepartmentStaffCount(APIView):
    @method_decorator(cache_page(60 * 15))
    def get(self, request):
        datas =OADepartment.objects.annotate(staff_count=Count('department_staffs')).values("name", "staff_count")

        return Response(datas)