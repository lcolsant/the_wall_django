# -*- coding: utf-8 -*-
# Generated by Django 1.11.12 on 2018-04-18 21:55
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('wall', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='message',
            old_name='user',
            new_name='user_name',
        ),
    ]
