from rest_framework import serializers
from django.contrib.auth.models import User
from  .  import models
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect,get_object_or_404









class ItemSerializer(serializers.ModelSerializer):
    class Meta:
        model=models.Item
        fields='__all__'
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# actor serializer:
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
class ActorSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Actor
        fields = '__all__'

#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# user serializers:
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email',)
        extra_kwargs = {
            'password': {'write_only': True}
                       }
    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(password=make_password(password), **validated_data)
        return user
      
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# member serializer:
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
class MemberSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    class Meta:
        model = models.Member
        fields = '__all__' 
 
    
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# notification serializer:
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
class NotificationSerializer(serializers.ModelSerializer):
    recepteur = MemberSerializer(read_only=True)
    class Meta:
        model = models.Notification
        fields = '__all__' 
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# benevole serializer:
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°  
class BenevoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Benevole
        fields = '__all__'
        read_only_fields = ('Date_inscript',)
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# beneficiaire serializer:
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
class BeneficiaireSerializer(serializers.ModelSerializer):
    SIT_SOCIALE_CHOICES = [
        ('victime_catastrophe_nat', 'VICTIME_CATASTROPHE_NATURELLE', 1),
        ('hospitalisé', 'HOSPITALISE', 2),
        ('malade', 'MALADE', 3),
        ('sans_abri', 'SANS_ABRI', 4),
        ('pauvre', 'PAUVRE', 5),
        ('handicapé', 'HANDICAPE', 7),
        ('cancéreux', 'CANCEREUX', 8),
        ('orphelin', 'ORPHELIN', 9),
        ('autiste', 'AUTISTE', 10),
        ('sans_etude', 'SANS_ETUDE', 11),
        ('eleve', 'ELEVE', 12),
        ('veuve', 'VEUVE', 13),
        ('besoin_particulier', 'BESOIN_PARTICULIER', 14),
    ]
    sit_sociale = serializers.ChoiceField(choices=[(c[0], c[1]) for c in SIT_SOCIALE_CHOICES])
    sit_sociale_priority = serializers.SerializerMethodField()

    class Meta:
        model = models.Beneficiaire
        fields = ['id','Nom','Prenom','Age','Date_Naissance','Adresse','Num_tel','Sexe','sit_sociale','sit_sociale_priority','date_ben','nb_ben','email']
        
    
    def create(self, validated_data):
        sit_sociale_data = validated_data.pop('sit_sociale')
        beneficiaire = models.Beneficiaire.objects.create(sit_sociale=sit_sociale_data, **validated_data)
        return beneficiaire

    def update(self, instance, validated_data):
        sit_sociale_data = validated_data.pop('sit_sociale')
        instance.sit_sociale = sit_sociale_data
        instance = super().update(instance, validated_data)
        return instance

    def get_sit_sociale_priority(self, obj):
        for choice in self.SIT_SOCIALE_CHOICES:
            if choice[0] == obj.sit_sociale:
                return choice[2]
        return None
    
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# partenaire serializer:
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
class PartenaireSerializer(serializers.ModelSerializer):
    respo_partner=ActorSerializer()
    class Meta:
        model = models.Partenaire
        fields = '__all__'
        
    def create(self, validated_data):
        respo_partner_data = validated_data.pop('respo_partner')
        respo_partner = models.Actor.objects.create(**respo_partner_data)
        partenaire = models.Partenaire.objects.create(respo_partner=respo_partner, **validated_data)
        return partenaire
    
    def update(self, instance, validated_data):
        respo_partner_data = validated_data.pop('respo_partner', None)
        if respo_partner_data:
            respo_partner = instance.respo_partner
            for key, value in respo_partner_data.items():
                setattr(respo_partner, key, value)
            respo_partner.save()

        for key, value in validated_data.items():
            setattr(instance, key, value)

        instance.save()
        return instance  
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# dmd_inscript serializer:
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
class Dmd_inscriptSerializer(serializers.ModelSerializer):
    demandeur=ActorSerializer()
    class Meta:
        model = models.Dmd_inscript
        fields = '__all__'

    def create(self, validated_data):
        demandeur_data = validated_data.pop('demandeur')
        demandeur = models.Actor.objects.create(**demandeur_data)
        dmd_inscript = models.Dmd_inscript.objects.create(demandeur=demandeur, **validated_data)
        return dmd_inscript  
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# msg_aide serializer:
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°     
class Msg_aideSerializer(serializers.ModelSerializer):

    SIT_SOCIALE_CHOICES = [
    ('victime_catastrophe_nat', 'VICTIME_CATASTROPHE_NATURELLE', 1),
    ('hospitalisé', 'HOSPITALISE', 2),
    ('malade', 'MALADE', 3),
    ('sans_abri', 'SANS_ABRI', 4),
    ('pauvre', 'PAUVRE', 5),
    ('handicapé', 'HANDICAPE', 7),
    ('cancéreux', 'CANCEREUX', 8),
    ('orphelin', 'ORPHELIN', 9),
    ('autiste', 'AUTISTE', 10),
    ('sans_etude', 'SANS_ETUDE', 11),
    ('eleve', 'ELEVE', 12),
    ('veuve', 'VEUVE', 13),
    ('besoin_particulier', 'BESOIN_PARTICULIER', 14),
]
    
    sit_sociale = serializers.ChoiceField(choices=[(c[0], c[1]) for c in SIT_SOCIALE_CHOICES])
    sit_sociale_priority = serializers.SerializerMethodField()
    benefic_info=ActorSerializer()


    def create(self, validated_data):
        benefic_info_data = validated_data.pop('benefic_info')
        benefic_info = models.Actor.objects.create(**benefic_info_data)
        msg_aide = models.Msg_aide.objects.create(benefic_info=benefic_info, **validated_data)
        return msg_aide
    
    def get_sit_sociale_priority(self, obj):
        for choice in self.SIT_SOCIALE_CHOICES:
            if choice[0] == obj.sit_sociale:
               return choice[2]
        return None
 
    class Meta:
        model = models.Msg_aide
        fields = '__all__'

#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# message serializer:
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
class MessageSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = models.Message
        fields = '__all__'
       
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# donations serializers:
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
class DonateurSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Donateur
        fields = ['Sexe','ccp_compte_num','numero_carte','exp_date',
                  'Nom','cvv','email',
                  'Prenom',
                  'Age','Adresse','Num_tel',]   

   
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# events serializers:
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
class VideoSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Video
        fields = '__all__'
    
#--------------------------------------------------------------------------------------------------
class imgSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.img
        fields = '__all__'
    
#--------------------------------------------------------------------------------------------------
class EventSerializer(serializers.ModelSerializer):
    #images = serializers.HyperlinkedRelatedField(view_name='img-detail', many=True,read_only=True)
    #videos = serializers.HyperlinkedRelatedField(view_name='Video-detail', many=True,read_only=True)
    #chef_equipe = serializers.HyperlinkedRelatedField(view_name='member-detail',read_only=True)
    #equipe = serializers.HyperlinkedRelatedField(view_name='member-detail', many=True,read_only=True)
    #benef_list = serializers.HyperlinkedRelatedField(view_name='Beneficiaire-detail', many=True,read_only=True)
    #benevole_list = serializers.HyperlinkedRelatedField(view_name='Benevole-detail', many=True,read_only=True)
    #partenaires = serializers.HyperlinkedRelatedField(view_name='Partenaire-detail', many=True,read_only=True)

    class Meta:
        model = models.Event
        fields = ['id','titre','date_début',
                  'date_fin','lieu','descript',
                  'somm_collect','donation_goal',
                  'chef_equipe','equipe','images','videos',
                  'benef_list','benevole_list','partenaires','list_besoin']
        
    def update(self, instance, validated_data):
        # Update the instance with the validated data

        instance.titre = validated_data.get('titre', instance.titre)
        instance.date_début = validated_data.get('date_début', instance.date_début)
        instance.date_fin = validated_data.get('date_fin', instance.date_fin)
        instance.lieu = validated_data.get('lieu', instance.lieu)
        instance.descript = validated_data.get('descript', instance.descript)
        instance.images.set(validated_data.get('images', instance.images.all()))
        instance.videos.set(validated_data.get('videos', instance.videos.all()))
        instance.list_besoin = validated_data.get('list_besoin', instance.list_besoin)
        instance.somm_collect = validated_data.get('somm_collect', instance.somm_collect)
        instance.donation_goal = validated_data.get('donation_goal', instance.donation_goal)
        instance.chef_equipe = validated_data.get('chef_equipe', instance.chef_equipe)
        instance.equipe.set(validated_data.get('equipe', instance.equipe.all()))
        instance.benef_list.set(validated_data.get('benef_list', instance.benef_list.all()))        
        instance.benevole_list.set(validated_data.get('benevole_list', instance.benevole_list.all()))
        instance.partenaires.set(validated_data.get('partenaires', instance.partenaires.all()))

        # Save the updated instance
        instance.save()

        return instance
       
#°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
#--------------------------------------------------------------------------------------------------
class Don_argentSerializer(serializers.ModelSerializer):
    donateur=DonateurSerializer()
    event = serializers.SlugRelatedField(slug_field='titre', queryset=models.Event.objects.all(), allow_null=True, required=False) 
    class Meta:
        model = models.Don_argent
        fields = '__all__'  

    def create(self, validated_data):
        donateur_data = validated_data.pop('donateur')
        donateur = models.Donateur.objects.create(**donateur_data)
        Don_argent = models.Don_argent.objects.create(donateur=donateur, **validated_data)
        return Don_argent

    def update(self, instance, validated_data):
        donateur_data = validated_data.pop('donateur', None)
        if donateur_data:
            donateur = instance.donateur
            for key, value in donateur_data.items():
                setattr(donateur, key, value)
            donateur.save()

        for key, value in validated_data.items():
            setattr(instance, key, value)

        instance.save()
        return instance 
##--------------------------------------------------------------------------------------------------
class Don_chosesSerializer(serializers.ModelSerializer):
    donateur=DonateurSerializer()
    event = serializers.SlugRelatedField(slug_field='titre', queryset=models.Event.objects.all(), allow_null=True, required=False)
    class Meta:
        model = models.Don_choses
        fields = '__all__'
        
    def create(self, validated_data):
        donateur_data = validated_data.pop('donateur')
        donateur = models.Donateur.objects.create(**donateur_data)
        Don_choses = models.Don_choses.objects.create(donateur=donateur, **validated_data)
        return Don_choses 
    
    def update(self, instance, validated_data):
        donateur_data = validated_data.pop('donateur', None)
        if donateur_data:
            donateur = instance.donateur
            for key, value in donateur_data.items():
                setattr(donateur, key, value)
            donateur.save()

        for key, value in validated_data.items():
            setattr(instance, key, value)

        instance.save()
        return instance
#--------------------------------------------------------------------------------------------------
class DonSerializer(serializers.ModelSerializer):
    event = serializers.SlugRelatedField(slug_field='titre', queryset=models.Event.objects.all(), allow_null=True, required=False)
    class Meta:
        model = models.Don
        fields = '__all__'
#--------------------------------------------------------------------------------------------------
class DonationSerializer(serializers.ModelSerializer):
    #events = serializers.PrimaryKeyRelatedField(queryset=models.Event.objects.all(), many=True, required=False)
    donateur = DonateurSerializer()
    dons_argent = Don_argentSerializer(many=True, required=False)
    dons_choses = Don_chosesSerializer(many=True, required=False)

    class Meta:
        model = models.Donation
        fields = '__all__'

    def create(self, validated_data):
        donateur_data = validated_data.pop('donateur')
        donateur = models.Donateur.objects.create(**donateur_data)
        donation = models.Donation.objects.create(donateur=donateur, **validated_data)
        return donation
    
    def update(self, instance, validated_data):
        donateur_data = validated_data.pop('donateur', None)
        dons_argent_data = validated_data.pop('dons_argent', [])
        dons_choses_data = validated_data.pop('dons_choses', [])
        
        # Update donateur instance if data is provided
        if donateur_data:
            donateur_serializer = DonateurSerializer(instance=instance.donateur, data=donateur_data)
            if donateur_serializer.is_valid(raise_exception=True):
                donateur_serializer.save()

        # Update dons_argent instances if data is provided
        for index, don_argent_data in enumerate(dons_argent_data):
            don_argent_instance = instance.dons_argent[index]
            don_argent_serializer = Don_argentSerializer(instance=don_argent_instance, data=don_argent_data)
            if don_argent_serializer.is_valid(raise_exception=True):
                don_argent_serializer.save()

        # Update dons_choses instances if data is provided
        for index, don_choses_data in enumerate(dons_choses_data):
            don_choses_instance = instance.dons_choses[index]
            don_choses_serializer = Don_chosesSerializer(instance=don_choses_instance, data=don_choses_data)
            if don_choses_serializer.is_valid(raise_exception=True):
                don_choses_serializer.save()

        return super().update(instance, validated_data)
