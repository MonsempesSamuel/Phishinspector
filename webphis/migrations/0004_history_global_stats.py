# Generated by Django 3.1.4 on 2020-12-24 10:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webphis', '0003_auto_20201221_2110'),
    ]

    operations = [
        migrations.CreateModel(
            name='History_Global_Stats',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateField(auto_now=True)),
                ('sha1_hex', models.CharField(max_length=40)),
                ('count_rows', models.IntegerField()),
            ],
        ),
    ]
