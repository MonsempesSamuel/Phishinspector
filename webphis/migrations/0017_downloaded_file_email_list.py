# Generated by Django 3.1.4 on 2021-01-18 17:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webphis', '0016_auto_20210118_1529'),
    ]

    operations = [
        migrations.AddField(
            model_name='downloaded_file',
            name='email_list',
            field=models.CharField(blank=True, max_length=3000),
        ),
    ]