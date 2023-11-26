from django.contrib import admin
from . import models

# models in admin panel
admin.site.register(models.Actor)
admin.site.register(models.Member)
#------------------------------------------
admin.site.register(models.Benevole)
admin.site.register(models.Beneficiaire)
admin.site.register(models.Partenaire)
admin.site.register(models.Item)
#------------------------------------------
admin.site.register(models.Event)
admin.site.register(models.Video)
admin.site.register(models.img)
#------------------------------------------
admin.site.register(models.Message)
admin.site.register(models.Msg_aide)
admin.site.register(models.Dmd_inscript)
admin.site.register(models.Notification)
#------------------------------------------
admin.site.register(models.Donateur)
admin.site.register(models.Donation)
admin.site.register(models.Don)
admin.site.register(models.Don_argent)
admin.site.register(models.Don_choses)
#------------------------------------------
