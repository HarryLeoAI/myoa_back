# Generated by Django 5.1.6 on 2025-02-16 10:45

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AbsentType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64)),
                ('create_time', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='Absent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=128)),
                ('content', models.TextField()),
                ('status', models.IntegerField(choices=[(1, 'Review'), (2, 'Agreed'), (3, 'Reject')], default=1)),
                ('start_date', models.DateField()),
                ('end_date', models.DateField()),
                ('create_time', models.DateTimeField(auto_now_add=True)),
                ('response_content', models.TextField()),
                ('requester', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='my_absents', related_query_name='my_absents', to=settings.AUTH_USER_MODEL)),
                ('responder', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='sub_absents', related_query_name='sub_absents', to=settings.AUTH_USER_MODEL)),
                ('absent_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='absents', related_query_name='absents', to='absent.absenttype')),
            ],
        ),
    ]
