# Generated by Django 4.1.7 on 2023-05-11 19:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webapp', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='actor',
            name='Sexe',
            field=models.CharField(blank=True, choices=[('M', 'Mmasculin'), ('F', 'féminin')], default='Mmasculin', max_length=20, verbose_name='Sexe'),
        ),
    ]