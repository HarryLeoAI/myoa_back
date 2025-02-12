from django.core.management.base import BaseCommand
from apps.oaauth.models import OAUser, OADepartment


class Command(BaseCommand):
    def handle(self, *args, **options):
        # 获取部门
        boarder = OADepartment.objects.get(name='董事会')
        developer = OADepartment.objects.get(name='研发部')
        operator = OADepartment.objects.get(name='运营部')
        salar = OADepartment.objects.get(name='销售部')
        human_resource = OADepartment.objects.get(name='人事部')
        finance = OADepartment.objects.get(name='财务部')

        # 董事会成员, 都是superuser
        chairman = OAUser.objects.create_superuser(email='harry.leo.ai@gmail.com', realname='刘浩宇', password='111111',
                                                   department=boarder)  # 董事会主席
        vice_chairman = OAUser.objects.create_superuser(email='harry_leo_ai@qq.com', realname='刘浩', password='111111',
                                                        department=boarder)  # 副主席

        # 各部门leader, 都是普通用户
        # 研发部
        zhang_san = OAUser.objects.create_user(email='zhangsan@qq.com', realname='张三', password='111111',
                                               department=developer)
        # 运营部
        li_si = OAUser.objects.create_user(email='lisi@qq.com', realname='李四', password='111111', department=operator)
        # 销售部
        wang_wu = OAUser.objects.create_user(email='wangwu@qq.com', realname='王五', password='111111',
                                             department=salar)
        # 人事部
        zhao_liu = OAUser.objects.create_user(email='zhaoliu@qq.com', realname='赵六', password='111111',
                                              department=human_resource)
        # 财务部
        sun_qi = OAUser.objects.create_user(email='sunqi@qq.com', realname='孙七', password='111111',
                                            department=finance)

        # 指定部门的 leader 和 manager
        boarder.leader = chairman
        boarder.manager = None

        # 董事长刘浩宇管理 研发, 运营, 销售部
        developer.leader = zhang_san
        developer.manager = chairman

        operator.leader = li_si
        operator.manager = chairman

        salar.leader = wang_wu
        salar.manager = chairman

        # 副董事长刘浩管理 人事部 和 财务部
        human_resource.leader = zhao_liu
        human_resource.manager = vice_chairman

        finance.leader = sun_qi
        finance.manager = vice_chairman

        boarder.save()
        developer.save()
        operator.save()
        salar.save()
        human_resource.save()
        finance.save()

        self.stdout.write('初始用户创建成功!')