"""
absent公共函数库
"""
def get_responder(user):
    """
    :param user:  当前登录用户, 请从 request.user中获取
    :return:      当前用户发起考勤(请假)时的审批者
    """
    if user.department.leader.uid == user.uid:
        if user.department.name == '董事会':
            responder = None
        else:
            responder = user.department.manager
    else:
        responder = user.department.leader

    return responder