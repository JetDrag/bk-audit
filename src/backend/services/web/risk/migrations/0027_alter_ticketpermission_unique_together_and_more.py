# Generated by Django 4.2.19 on 2025-07-04 06:45

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('risk', '0026_risk_created_at_risk_created_by_risk_updated_at_and_more'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='ticketpermission',
            unique_together=set(),
        ),
        migrations.AddField(
            model_name='ticketpermission',
            name='user',
            field=models.CharField(db_index=True, max_length=255, verbose_name='User'),
        ),
        migrations.AddField(
            model_name='ticketpermission',
            name='user_type',
            field=models.CharField(
                choices=[('operator', 'Operator'), ('notice_user', 'Notice User')],
                db_index=True,
                max_length=32,
                verbose_name='User Type',
            ),
        ),
        migrations.RunPython(
            code=lambda apps, schema_editor: apps.get_model('risk', 'TicketPermission')
            .objects.all()
            .update(user=models.F('operator'), user_type='operator'),
            reverse_code=lambda apps, schema_editor: None,
        ),
        migrations.AlterUniqueTogether(
            name='ticketpermission',
            unique_together={('risk_id', 'action', 'user', 'user_type')},
        ),
        migrations.RemoveField(
            model_name='ticketpermission',
            name='operator',
        ),
    ]
