from django.core.management.base import BaseCommand
from apps.absent.models import AbsentType


class Command(BaseCommand):
    def handle(self, *args, **options):
        absent_list = ["事假", "病假", "工伤假", "婚假", "丧假", "产假", "探亲假", "公假", "年休假"]
        absents_types = []
        for name in absent_list:
            absents_types.append(AbsentType(name=name))
        AbsentType.objects.bulk_create(absents_types)
        self.stdout.write('考勤类型数据初始化成功！')