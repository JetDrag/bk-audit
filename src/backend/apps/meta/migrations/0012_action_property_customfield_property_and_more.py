# Generated by Django 4.2.19 on 2025-04-01 11:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('meta', '0011_alter_systemdiagnosisconfig_push_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='action',
            name='property',
            field=models.JSONField(default=dict, verbose_name='通用属性列'),
        ),
        migrations.AddField(
            model_name='customfield',
            name='property',
            field=models.JSONField(default=dict, verbose_name='通用属性列'),
        ),
        migrations.AddField(
            model_name='datamap',
            name='property',
            field=models.JSONField(default=dict, verbose_name='通用属性列'),
        ),
        migrations.AddField(
            model_name='field',
            name='property',
            field=models.JSONField(default=dict, verbose_name='通用属性列'),
        ),
        migrations.AddField(
            model_name='globalmetaconfig',
            name='property',
            field=models.JSONField(default=dict, verbose_name='通用属性列'),
        ),
        migrations.AddField(
            model_name='namespace',
            name='property',
            field=models.JSONField(default=dict, verbose_name='通用属性列'),
        ),
        migrations.AddField(
            model_name='resourcetype',
            name='property',
            field=models.JSONField(default=dict, verbose_name='通用属性列'),
        ),
        migrations.AddField(
            model_name='sensitiveobject',
            name='property',
            field=models.JSONField(default=dict, verbose_name='通用属性列'),
        ),
        migrations.AddField(
            model_name='system',
            name='property',
            field=models.JSONField(default=dict, verbose_name='通用属性列'),
        ),
        migrations.AddField(
            model_name='systemdiagnosisconfig',
            name='property',
            field=models.JSONField(default=dict, verbose_name='通用属性列'),
        ),
        migrations.AddField(
            model_name='systemrole',
            name='property',
            field=models.JSONField(default=dict, verbose_name='通用属性列'),
        ),
        migrations.AddField(
            model_name='tag',
            name='property',
            field=models.JSONField(default=dict, verbose_name='通用属性列'),
        ),
    ]
