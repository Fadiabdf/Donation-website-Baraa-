# Generated by Django 4.1.7 on 2023-05-11 19:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webapp', '0002_alter_actor_sexe'),
    ]

    operations = [
        migrations.AlterField(
            model_name='actor',
            name='Sexe',
            field=models.CharField(blank=True, choices=[('M', 'Masculin'), ('F', 'Féminin')], default='Masculin', max_length=20, verbose_name='Sexe'),
        ),
    ]
