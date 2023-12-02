# imports :
from decimal import Decimal
from django.db import models
from ckeditor.fields import RichTextField
from django.contrib.auth.models import User
#-----------------------------------------------------------------------------
from django.conf import settings
#-----------------------------------------------------------------------------
from django.core.validators import MinValueValidator, MaxValueValidator
from phonenumber_field.modelfields import PhoneNumberField
from django.core.validators import RegexValidator
from django_countries.fields import CountryField
from enum import Enum

#-------------------------------------------------------------------------
# models :
#------------------------------------------------------------------------- 
#####################################################################################################   
#---------------------------------------------------------------------------------------
# actor model
#---------------------------------------------------------------------------------------
class Actor(models.Model):
    
    Nom= models.CharField(max_length=50, verbose_name='Nom',null=True,blank=True) 
    Prenom= models.CharField(max_length=50, verbose_name='Prénom',null=True,blank=True)  
    Age = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(120)], verbose_name='Age',null=True,blank=True)#positive
    Date_Naissance = models.DateField(verbose_name='Date de naissance',null=True,blank=True) 
    Adresse= models.CharField(max_length=150, verbose_name='Adresse',null=True,blank=True)  
    Num_tel= PhoneNumberField(null=True, blank=True, unique=False,verbose_name='Numéro du téléphone') 
    
    GENDER_CHOICES = (('M', 'Masculin'), ('F', 'Féminin'))
    Sexe = models.CharField(max_length=20, choices=GENDER_CHOICES, default='Masculin', verbose_name='Sexe',blank=True)
    Pays = CountryField(verbose_name='Pays',blank=True,null=True)  
    
    def __str__(self):
       return self.Nom+' '+self.Prenom  
    class Meta:
       verbose_name = 'Acteurs'
       ordering = ['-Age']
####################################################################################################
class Dmd_inscript(models.Model): # join us 
      
      TYPES_CHOICES = [('B', 'Bénévole'),('M', 'Membre'),('P','Partenaire'),] 
      demandeur=models.OneToOneField(Actor,on_delete=models.CASCADE,null=True)
      email= models.EmailField(unique=False,null=True,blank=True,verbose_name='email')# pour le contacter
      '''
      demandeur(acteur) --> member/volenteer/partner (acteur)
      '''
      type = models.CharField(max_length=20, choices=TYPES_CHOICES)
      date_dmd = models.DateTimeField(auto_now_add=True)
      motivation= models.TextField(null=True, blank=True)
      statut_dmd = models.BooleanField(default=False, choices=((False, 'pas traitée'), (True, 'traitée')))
      Nom_org=models.CharField(max_length=100,null=True)
      def __str__(self):
       return self.demandeur.Nom+' '+self.demandeur.Prenom+' as a '+self.type
      
      class Meta:
       verbose_name = 'demandes inscription'
       ordering = ['-date_dmd']
      #******************************************
      def update_demand_status(dmd_id):
        dmd = Dmd_inscript.objects.get(id=dmd_id)
        dmd.statut_dmd = True
        dmd.save()
####################################################################################################
#---------------------------------------------------------------------------------------
# message (random) models
#---------------------------------------------------------------------------------------
class Message(models.Model): # for random messages  and feedbacks

    sender_name=models.CharField(null=False,max_length=100)
    sender_email=models.EmailField(null=True, blank=True,verbose_name='email',unique=False)
    date_envoie=models.DateTimeField(auto_now_add=True)
    Contenu_msg=RichTextField(null=True, blank=True)
    updated = models.DateTimeField(auto_now=True)
    
    def __str__(self):
       return self.sender_name 
 
    class Meta:
       verbose_name = 'Message de contact'
       ordering = ['date_envoie']
       
####################################################################################################
#---------------------------------------------------------------------------------------
# member  models
#---------------------------------------------------------------------------------------

class Role(models.TextChoices):
    GERANT = 'gérant'
    COMPTABLE = 'comptable'
    TRANSPORTEUR ='transporteur'
    ADMIN ='admin'
    RESPENSABLE_EVENT='respensable evenement'
    ORGANISATEUR ='organisateur'
    ANNANCEUR = 'annonceur'
    MEMBER = 'membre'
#####################################################################################################
class Member (Actor):

    user = models.OneToOneField(User, on_delete=models.CASCADE,verbose_name='le compte')
    '''
    user (id,username,password,email)
    '''
    date_iscript=models.DateField('inscription date')
    photo_profil=models.ImageField(upload_to='members_imgs/',null=True,blank=True)
    role = models.CharField(max_length=50, choices=Role.choices,default=Role.MEMBER.value)
    actif = models.BooleanField(default=True, choices=((False, 'inactif'), (True, 'actif')))

    @staticmethod
    def calculate_total_member_list():
        total_member = 0
        members = Member.objects.all()
        total_member= members.count()
        return total_member
    
    def __str__(self):
       return self.user.username+' '+self.Nom+' '+self.Prenom
    #************************************
    def update_role(self, new_role):
        if new_role in Member.Role.values:
            self.role = new_role
            self.save()  
        
    class Meta:
       verbose_name = 'membres'
       ordering = ['-date_iscript']

####################################################################################################
#---------------------------------------------------------------------------------------
# notification models
#---------------------------------------------------------------------------------------
class NotificationType(models.TextChoices):

    ROLE_UPDATED = 'role_updated'
    ANNOUNCEMENT = 'announcement'
    NEW_MESSAGE = 'new_message'
    ACCEPTANCE ='request_accepted'
##############################################################################
class Notification(models.Model):

    contenu = RichTextField(null=True, blank=True)
    recepteur = models.ForeignKey(Member, on_delete=models.CASCADE, verbose_name ='notif to',related_name='recepteur',null=True)
    date_envoi = models.DateTimeField(auto_now_add=True)
    is_checked = models.BooleanField(default=False)
    type = models.CharField(max_length=50, choices=NotificationType.choices, null=True, blank=True,verbose_name='notification for :')

    class Meta:
        ordering = ['-date_envoi']

#################################################################################################### 

#---------------------------------------------------------------------------------------
# partenaire model
#---------------------------------------------------------------------------------------
class Partenaire(models.Model): 
     
     respo_partner=models.OneToOneField(Actor,on_delete=models.CASCADE, verbose_name ='le partenaire',null=True)
     Nom_org = models.CharField(max_length=50) 
     Descript_org = RichTextField(null=True,blank=True,verbose_name='description')
     Date_collab= models.DateTimeField(auto_now_add=True)
     logo=models.ImageField(upload_to='partenaires_imgs/',null=True)
     email=models.EmailField(unique=False,default=None)
     def __str__(self):
       return self.Nom_org
     class Meta:
        ordering = ['Date_collab'] 
#-------------------------------------------------------------------------------------------------------------
# benevole model
#-------------------------------------------------------------------------------------------------------------
class Benevole(Actor):
    Date_inscript = models.DateTimeField(auto_now_add=True)
    bénévolat = RichTextField(null=True, blank=True)
    email= models.EmailField(unique=False,null=True,blank=False,verbose_name='contact')# pour le contacter

    def __str__(self):
       return self.Nom+' '+self.Prenom
    
    class Meta:
       verbose_name = 'bénévoles'
       ordering = ['-Date_inscript']
####################################################################################################
#------------------------------------------------------------------------------------------------
# beneficiaire model
#---------------------------------------------------------------------------------------
class Beneficiaire(Actor):
     
    SIT_SOCIALE_CHOICES = [
        ('victime_catastrophe_nat', 'VICTIME_CATASTROPHE_NATURELLE'),
        ('hospitalisé', 'HOSPITALISE'),
        ('malade', 'MALADE'),
        ('sans_abri', 'SANS_ABRI'),
        ('pauvre', 'PAUVRE'),
        ('handicapé', 'HANDICAPE'),
        ('cancéreux', 'CANCEREUX'),
        ('orphelin', 'ORPHELIN'),
        ('autiste', 'AUTISTE'),
        ('sans_etude', 'SANS_ETUDE'),
        ('eleve', 'ELEVE'),
        ('veuve', 'VEUVE'),
        ('besoin_particulier', 'BESOIN_PARTICULIER'),
    ]

    sit_sociale= models.CharField(max_length=100, choices= SIT_SOCIALE_CHOICES ,null=True, blank=True)
    date_ben= models.DateTimeField(auto_now_add=True,verbose_name='Date de bénéfice') 
    nb_ben= models.PositiveIntegerField( default = 0,verbose_name='nombre de bénéfices',null=True,blank=True)
    email= models.EmailField(unique=False,null=True,blank=False,verbose_name='contact')# pour le contacter
    

    def __str__(self):
       return self.Nom+' '+self.Prenom
    
    class Meta:
       verbose_name = 'Beneficiaires'
       ordering = ['date_ben']

#-------------------------------------------------------------------------------------------------------------
#message d'aide model
#-------------------------------------------------------------------------------------------------------------
class Msg_aide(Message):  # for get help
     
     RELATION_CHOICES = [  # il a besoin d'aide :
        ('moi_meme', 'Moi même'),
        ('ami', 'Ami'),
        ('college', 'Collége'),
        ('fils', 'Fils'),
        ('voisin', 'Voisin'),
        ('autre', 'Autre'),
    ]
     SIT_SOCIALE_CHOICES = [
        ('victime_catastrophe_nat', 'VICTIME_CATASTROPHE_NATURELLE'),
        ('hospitalisé', 'HOSPITALISE'),
        ('malade', 'MALADE'),
        ('sans_abri', 'SANS_ABRI'),
        ('pauvre', 'PAUVRE'),
        ('handicapé', 'HANDICAPE'),
        ('cancéreux', 'CANCEREUX'),
        ('orphelin', 'ORPHELIN'),
        ('autiste', 'AUTISTE'),
        ('sans_etude', 'SANS_ETUDE'),
        ('eleve', 'ELEVE'),
        ('veuve', 'VEUVE'),
        ('besoin_particulier', 'BESOIN_PARTICULIER'),
    ]

     sit_sociale= models.CharField(max_length=100, choices= SIT_SOCIALE_CHOICES ,null=True, blank=True)#le besoin 
     benefic_info  = models.OneToOneField(Actor, on_delete=models.CASCADE, verbose_name='Bénéficiaire', related_name='msg_aide',null=True, blank=True)
     relation = models.CharField(max_length=20, choices=RELATION_CHOICES,verbose_name='la relation du bénéficiaire concerné avec l\'emmeteur') 
     descript_besoin= RichTextField(verbose_name= 'les besoins du benéficiaire',null=True )
     Statut_msg= models.BooleanField(max_length=10, choices=((False, 'pas vue'), (True, ' vue')), default=False, verbose_name='Status message')
     
     
     class Meta:
       verbose_name = 'Message  aide'   
#######################################################################################################
#---------------------------------------------------------------------------
# event models
#----------------------------------------------------------------------------------
##################################################################
class Video(models.Model):
    filename = models.CharField(max_length=100,null=True,blank=True)
    video_file = models.FileField(upload_to='event_vd',null=True,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.filename  
##############################################################################################
class img(models.Model):
    filename = models.CharField(max_length=100,null=True,blank=True)
    image = models.ImageField(upload_to='event_img',null=True,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.filename 
################################################################################
class Event(models.Model):

    titre = models.CharField(max_length=100, default='Titre_évènement',null=False,blank=False)
    date_début = models.DateTimeField('Date et heure début évènement',null=True,blank=False)
    date_fin= models.DateTimeField('Date et heure fin évènement',null=True,blank=True)
    lieu = models.CharField(max_length=200,null=True,blank=True)
    descript = RichTextField(null=True,blank=True,verbose_name='description')
    images = models.ManyToManyField(img, blank=True,verbose_name='photos  evenement')
    videos = models.ManyToManyField(Video, blank=True,verbose_name='videos  evenement')
    list_besoin=RichTextField(null=True,blank=True,verbose_name='liste des besoins')
    #-------------------------------------------------------------------------------------------------------
    somm_collect =models.DecimalField(max_digits=10,decimal_places=4,default= 0.00,null=True,blank=True)
    donation_goal = models.DecimalField(max_digits=10, decimal_places=4, verbose_name="Montant souhaité des dons (DZD)",null=True,blank=True)
    #-------------------------------------------------------------------------------------------------------
    chef_equipe = models.ForeignKey(Member, on_delete=models.CASCADE, verbose_name='chef  evenement',null=True,blank=False,limit_choices_to={'role': Role.RESPENSABLE_EVENT})
    equipe = models.ManyToManyField(Member, related_name='event_equipe', blank=True)
    #-------------------------------------------------------------------------------------------------------
    benef_list = models.ManyToManyField(Beneficiaire, blank=True)
    benevole_list = models.ManyToManyField(Benevole, related_name='participants', blank=True)
    #-------------------------------------------------------------------------------------------------------
    partenaires= models.ManyToManyField(Partenaire, blank=True,default=None)
    #-------------------------------------------------------------------------------------------------------
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True,null=True)
##################################################################
    @staticmethod
    def calculate_total_event_list():
        total_event = 0
        events = Event.objects.all()
        total_event= events.count()
        return total_event

######################################################################
    @staticmethod
    def calculate_total_amount_collected():
        total_amount = Decimal('0.00')
        events = Event.objects.all()
        for event in events:
            if event.somm_collect is not None:
               total_amount += event.somm_collect
        return total_amount
#----------------------------------------
    @staticmethod
    def calculate_total_benef_list():
        total_benef = 0
        events = Event.objects.all()
        for event in events:
           if event.benef_list.exists():
              total_benef += event.benef_list.count()
        return total_benef
#############################################################################
    def __str__(self):
       return self.titre
##################################################################   
    class Meta:
       verbose_name = 'Mes evenements'
       ordering = ['-date_début'] 
##################################################################  
#-------------------------------------------------------------------------------------------------------------
# donations models
#-------------------------------------------------------------------------------------------------------------
class mode_paiment(Enum):
     CARTE_DAHABIA='catre eldahabia'
############################################################################################################################
class Donateur(Actor):
    ccp_compte_num = models.CharField(max_length=12, validators=[RegexValidator(regex=r'^\d{12}$', message='Le numéro de compte CCP doit contenir 12 chiffres')],null=True,blank=False)
    numero_carte = models.CharField(max_length=16, validators=[RegexValidator(regex=r'^\d{16}$', message='Le numéro de carte doit contenir 16 chiffres')],null=True,blank=True)
    exp_date = models.DateField(null=True,blank=True)
    cvv = models.PositiveIntegerField(null=True,blank=True,validators=[MinValueValidator(100), MaxValueValidator(999)])
    email= models.EmailField(unique=False,null=True,blank=True,verbose_name='email')# pour le contacter
    
    def __str__(self):
       return self.Nom+' '+self.Prenom   
        
    class Meta:
       verbose_name = 'donateurs'

####################################################################################################
class Don(models.Model):
     DON_CHOICES = [ ('money', 'give money'),('item', 'give item'), ]
     donateur =models.ForeignKey(Donateur,on_delete=models.CASCADE,null=True)
     date_donation=models.DateTimeField(auto_now_add=True,null=True,blank=True)
     type_don=models.CharField(max_length=20, choices=DON_CHOICES,verbose_name='type de don', null=True, blank=True)
     event = models.ForeignKey(Event, on_delete=models.CASCADE, blank=True, null=True)

     
     def __str__(self):
        return f"{self.type_don} de {self.donateur.Nom} {self.donateur.Prenom}" 
        
     class Meta:
       verbose_name = 'dons'
      
####################################################################################################
class Don_choses(Don): 
    Qte=models.PositiveIntegerField(verbose_name='Quantité')
    item = models.CharField(max_length=200,verbose_name='item')  
    descript=RichTextField(null=True,blank=True,verbose_name='description')
   
    class Meta:
       verbose_name = 'dons type choses'
####################################################################################################
class Don_argent(Don): 
     mode_paiement=models.CharField(choices=[(method.value, method.name) for method in mode_paiment], max_length=50)
     montant=models.DecimalField(max_digits=10, decimal_places=2, verbose_name="Montant du don (DZD)",null=False,blank=False)
    
     class Meta:
       verbose_name = 'dons type argent'
####################################################################################################
class Donation(models.Model):
    donateur =models.ForeignKey(Donateur,on_delete=models.CASCADE)
    dons_choses = models.ManyToManyField(Don_choses,blank=True)
    dons_argent= models.ManyToManyField(Don_argent,blank=True)
    
    
    def __str__(self):
       return self.donateur.Nom+' '+self.donateur.Prenom  
        
    class Meta:
       verbose_name = 'donations'
##############################################################################################################
class Item(models.Model):
    Qte=models.PositiveIntegerField(null=True,verbose_name='Quantité')
    item = models.CharField(max_length=200,verbose_name='item')  
    def __str__(self):
       return  f"{self.item} ({self.Qte})" 
#______________________________________________________________________________________________________________________




