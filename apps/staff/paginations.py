from rest_framework.pagination import PageNumberPagination

# Merchant的分页规则
class UserPagination(PageNumberPagination):
    """
    考勤分页配置
    """
    page_size = 10
    max_page_size = 10