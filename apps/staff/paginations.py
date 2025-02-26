from rest_framework.pagination import PageNumberPagination

# Merchant的分页规则
class UserPagination(PageNumberPagination):
    # 参数 ?page=x 以page关键字的值来规定每页数据
    page_query_param = "page"
    # 参数 &size=x 以size关键字的值来规定每页数据量
    page_size_query_param = 'size'
    # 默认10条每页
    page_size = 10
    # 最大20条每页
    max_page_size = 20