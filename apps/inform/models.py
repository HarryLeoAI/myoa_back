from django.db import models
from apps.oaauth.models import OAUser
from apps.oaauth.models import OADepartment

class Inform(models.Model):
    """
    通知表
    """
    # 标题
    title = models.CharField(max_length=128)
    # 内容
    content = models.TextField()
    # 创建时间
    create_time = models.DateTimeField(auto_now_add=True)
    # 是否公开
    public = models.BooleanField(default=False)
    # 发布人
    author = models.ForeignKey(OAUser, on_delete=models.CASCADE, related_name="informs", related_query_name="informs")
    # 可以看见这条通知的部门(department_ids): 如果包含0 ([0,...,]) 那么认为该通知所有部门可见(public=true)
    departments = models.ManyToManyField(OADepartment, related_name='informs', related_query_name='informs')

    class Meta:
        ordering = ('-create_time', )

class InformRead(models.Model):
    """
    阅读者
    """
    # 通知
    inform = models.ForeignKey(Inform, on_delete=models.CASCADE, related_name='been_read', related_query_name='been_read')
    # 用户
    user = models.ForeignKey(OAUser, on_delete=models.CASCADE, related_name='has_read', related_query_name='has_read')
    # 哪个用户读了哪条通知在什么时间
    read_time = models.DateTimeField(auto_now_add=True)

    class Meta:
        # 一个用户只能对一条通知进行有效阅读, 所以这两个字段组合起来必须是唯一的
        unique_together = ('inform', 'user')