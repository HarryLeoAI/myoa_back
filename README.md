# myoa_bacn 企业OA系统后台开发日志
- 后端基于Django Rest Framewordk

# 创建项目和基本配置
### 创建数据库
- `create database myoa;`, 略
### 创建项目
- 新建django项目, 选择虚拟环境, 并且安装好所需的包:
    - `pip install mysqlclient` => mysql数据库操作包
    - `pip install djangorestframework` => drf包
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
- 新建`.gitignore`, 声明 git 不追踪配置文件: `database.cnf`
### github托管
- github新建仓库`myoa_back`
- 本地项目根路径下执行以下命令:
    - `git init` 初始化仓库
    - `git add .` 添加更改项
    - `git commit -m "项目初始化"` 初次提交
    - `git remote add origin https://github.com/HarryLeoAI/myoa_back.git` 