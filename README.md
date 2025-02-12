# myoa_bacn 企业 OA 系统后台开发日志

- 后端基于 Django Rest Framewordk

# 创建项目和基本配置

### 创建数据库

- `create database myoa;`, 略

### 创建项目

- 新建 django 项目, 选择虚拟环境, 并且安装好所需的包:
  - `pip install mysqlclient` => mysql 数据库操作包
  - `pip install djangorestframework` => drf 包

### 配置

- `settings.py`

```python
# ...
# 时区配置
LANGUAGE_CODE = 'zh-hans' # 简体中文

TIME_ZONE = 'UTC' # 时区

USE_I18N = False # 非国际化项目

USE_TZ = False # 禁用时区

# ...
# 数据库配置
from pathlib import Path
import os

database_config = ConfigParser()
database_config.read(os.path.join(BASE_DIR, 'database.cnf'))
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': database_config.get('database', 'DB_NAME'),
        'USER': database_config.get('database', 'DB_USER'),
        'PASSWORD': database_config.get('database', 'DB_PASSWORD'),
        'HOST': database_config.get('database', 'DB_HOST'),
        'PORT': database_config.get('database', 'DB_PORT'),
    }
}

# ...
# 声明加载APP: rest_framework
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework', # 安装drf
]

# ...
# 禁用csrf中间件
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware', # 禁用CSRF
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

- 新建`~/database.cnf`

```
[database]
DB_NAME = 数据库名称
DB_USER = 数据库用户
DB_PASSWORD = 数据库密码
DB_HOST = 数据库主机,默认localhost
DB_PORT = 数据库端口,默认3306
```

> 配置文件中,所有值都不用引号,错误示范:`'root'`

- 新建`.gitignore`, 声明 git 不追踪配置文件: `database.cnf`

### github 托管

- github 新建仓库`myoa_back`
- 本地项目根路径下执行以下命令:
  - `git init` 初始化仓库
  - `git add .` 添加更改项
  - `git commit -m "项目初始化"` 初次提交
  - `git remote add origin https://github.com/HarryLeoAI/myoa_back.git` 添加远程仓库地址
  - `git push --set-upstream origin master` 推送更新到远程仓库仓库, 设置主分支


# 跨域请求配置
### django-cors-headers
- `django-cors-headers` 是一个用于处理跨源资源共享（CORS，Cross-Origin Resource Sharing）请求的 Django 中间件库。CORS 是一种机制，允许通过浏览器从一个域访问另一个域的资源。在开发 Web 应用时，尤其是前后端分离的架构中，通常会遇到跨域请求的问题，django-cors-headers 可以帮助解决这个问题。
### 安装
- `pip install django-cors-headers`
### 配置
- `settings.py`
```py
# ...加载app
INSTALLED_APPS = [
    # ...
    'rest_framework',
    'corsheaders', # 加载corshearders
]


# ...加载中间件, 注意应该放在
MIDDLEWARE = [
    # ...
    # 应该放在 CommonMiddleware 前
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    # ...
]


# ...简单配置
# cors配置
CORS_ALLOW_ALL_ORIGINS = True # 开发阶段暂时允许所有域名跨域请求
'''
# 实际投入使用时应该配置:
CORS_ALLOW_ALL_ORIGINS = False  # 默认情况下，禁用所有跨域请求
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",  # 前端vue默认的的URL
]

# 允许请求的方法
CORS_ALLOW_METHODS = [
    'GET',
    'POST',
    'PUT',
    'DELETE',
    'PATCH',
]

# 允许的请求头
CORS_ALLOW_HEADERS = [
    'content-type',
    'authorization',
    'x-csrftoken',
]

# 如果需要携带 Cookie 或认证信息
CORS_ALLOW_CREDENTIALS = True
'''
```