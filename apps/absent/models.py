from django.db import models
from django.contrib.auth import get_user_model

OAUser = get_user_model()

class AbsentStatusChoices(models.IntegerChoices):
    """
    请假状态
    1审批中
    2审核通过
    3拒绝
    """
    REVIEW = 1
    AGREED = 2
    REJECT = 3

class AbsentType(models.Model):
    """
    请假类型
    """
    name = models.CharField(max_length=64)
    create_time = models.DateTimeField(auto_now_add=True)

class Absent(models.Model):
    """
    考勤
    """
    # 请假标题
    title = models.CharField(max_length=128)
    # 请假内容
    content = models.TextField()
    # 请假类型
    absent_type = models.ForeignKey(AbsentType, on_delete=models.CASCADE, related_name='absents', related_query_name='absents')
    # 请假发起人
    requester = models.ForeignKey(OAUser, on_delete=models.CASCADE, related_name='my_absents', related_query_name='my_absents')
    # 请假审批人
    responder = models.ForeignKey(OAUser, on_delete=models.CASCADE, related_name='sub_absents', related_query_name='sub_absents', null=True)
    # 请假状态
    status = models.IntegerField(choices=AbsentStatusChoices, default=AbsentStatusChoices.REVIEW)
    # 请假起始日期
    start_date = models.DateField()
    # 请假结束日期
    end_date = models.DateField()
    # 请假发起时间
    create_time = models.DateTimeField(auto_now_add=True)
    # 审批回复内容
    response_content = models.TextField(blank=True)