# Generated by Django 5.0.3 on 2024-07-17 11:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_alter_customuser_role'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='role',
            field=models.CharField(choices=[('user', 'User'), ('shop owner', 'Shopowner')], default='user', max_length=20),
        ),
    ]
