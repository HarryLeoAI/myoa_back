from rest_framework import viewsets
from .models import Inform, InformRead
from .serializers import InformSerializer
from django.db.models import Q
from django.db.models import Prefetch
from .paginations import InformPagination

class InformViewSet(viewsets.ModelViewSet):
    queryset = Inform.objects.all()
    serializer_class = InformSerializer
    pagination_class = InformPagination

    def get_queryset(self):
        """
        ModelViewSet 视图集默认返回所有数据
        虽然可以通过.objects.filter('筛选条件').all()进行简单筛选
        但当逻辑过于复杂, 且需要进行多表多次查询时, 应该考虑重写get_queryset方法, 来实现更复杂数据库查询的逻辑

        现在项目的需求是:
        1, 查询时, 查找到相关的通知发布者的信息(数据库里的外键存的只是author_id, 而不是用户的全部信息): select_related()
        2, 查询时, 通过多对多关系, 找到当前登录用户, 是否已读过本条通知: prefetch_related()
        3, 查询时, 需要遵循以下逻辑:
            3.1, 要么是公开的
            3.2, 要么可见部门里有当前登录用户的所属部门
            3.3, 要么通知的作者就是当前登录的用户
        4. 最后不能用all(), 而是 distinct() 避免数据重复

        这么做的原因是为了尽可能少地访问数据库
        """
        queryset = (self
                    # 减少访问数据库: 提前找到通知发布者
                    .queryset.select_related('author')
                    # 减少访问数据库: 提前找到通知是否已读的相关信息
                    .prefetch_related(Prefetch("been_read", queryset=InformRead.objects.filter(user_id=self.request.user.uid)), 'departments')
                    # 筛选出来: 1是公开的, 2是通知可见部门里有用户所属部门的, 3是通知发布者是用户自己的 所有数据
                    .filter(Q(public=True) | Q(departments=self.request.user.department) | Q(author=self.request.user))
                    # .distinct() 是从数据库中获取不重复的记录
                    .distinct())
        return queryset