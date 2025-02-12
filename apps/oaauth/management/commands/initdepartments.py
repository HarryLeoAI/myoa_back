from django.core.management.base import BaseCommand
from apps.oaauth.models import OADepartment
class Command(BaseCommand):
    def handle(self, *args, **options):
        # 初始化部门数据
        boarder = OADepartment.objects.create(name='董事会', intro='董事会')
        developer = OADepartment.objects.create(name='研发部', intro='产品设计,技术开发')
        operator = OADepartment.objects.create(name='运营部', intro='产品和客户运营')
        salar = OADepartment.objects.create(name='销售部', intro='产品销售')
        human_resource = OADepartment.objects.create(name='人事部', intro='员工的招聘,培训,考核')
        finance = OADepartment.objects.create(name='财务部', intro='财会业务')
        self.stdout.write('部门数据初始化成功!')
