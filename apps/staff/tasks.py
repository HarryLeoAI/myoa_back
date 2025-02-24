from myoa_back import celery_app
from django.core.mail import EmailMultiAlternatives
from django.conf import settings

@celery_app.task(name="send_mail_task")
def send_mail_task(email, realname, active_url):
    # 配置邮箱内容
    subject = f"欢迎加入我们, {realname}!"
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = email
    html_content = f"""
            <html>
              <body>
                <h1>欢迎入职本公司!</h1>
                <p>您所属部门领导已为您创建好了OA系统账号,</p>
                <p><a href="{active_url}">请点击本链接进行账号激活!</a></p>
                <br>
                <p>如果上方链接无法正确访问? 请自行复制和粘贴下方链接到浏览器地址栏中手动打开!</p>
                <p>{active_url}</p>
              </body>
            </html>
            """

    # 发送邮件
    email_sender = EmailMultiAlternatives(
        subject=subject,
        body="",
        from_email=from_email,
        to=[to_email],
    )
    email_sender.attach_alternative(html_content, "text/html")
    email_sender.send()