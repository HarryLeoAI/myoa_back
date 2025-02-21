from rest_framework.pagination import PageNumberPagination

# Merchant的分页规则
class InformPagination(PageNumberPagination):
    """
    考勤分页配置
    """
    page_size = 5
    max_page_size = 5