#"""""""""""""""""""""""""""""""""""""""""
#        views.py
#"""""""""""""""""""""""""""""""""""""""""
from django.conf import settings
from django.core.mail import EmailMessage
import requests,random,string
from . import models
from . import serializers
from .serializers import (
      MemberSerializer,
	  NotificationSerializer,
	  PartenaireSerializer,
	  EventSerializer,
      BenevoleSerializer,
      DonationSerializer,
      DonSerializer,
	  Dmd_inscriptSerializer,
      BeneficiaireSerializer,
      DonateurSerializer,
      ItemSerializer,
      #UserSerializer
)
from django.db import transaction
from django.contrib.auth.models import User
#from social_django.models import SocialToken
from django.views.generic import View
#-----------------------------------------------------------------------------------------------------------------
from django.shortcuts import render, redirect,get_object_or_404
from django.utils import timezone
from datetime import datetime,date
from django.views.decorators.http import require_http_methods
from django.http import HttpResponse,JsonResponse
from django.template import loader
from django.template.loader import get_template
#-----------------------------------------------------------------------------------------------------------------
from django_filters.rest_framework import DjangoFilterBackend
#----------------------------------------------------------------------------------------------------------------------
import smtplib
from email.mime.text import MIMEText
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.db.models import Q
#from email.message import EmailMessage
from django.contrib import messages
#----------------------------------------------------------------------------------------------------------------------
import chargily_epay_django
#---------------------------------------------------------------------------------------------------------
from rest_framework import viewsets, mixins, status,generics,permissions,authentication,filters
from rest_framework.views import APIView 
from rest_framework.response import Response
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.decorators import action,api_view,permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
#----------------------------------------------------------------------------------------------------------------------
from django.contrib.auth.decorators import user_passes_test,login_required
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
#--------------------------------------------------------------------------------------------------------------
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.views import (OAuth2Adapter, OAuth2LoginView, OAuth2CallbackView)
#from social_django.views import OAuth2View
from social_django.utils import load_backend, load_strategy
from social_core.exceptions import AuthCanceled, AuthUnknownError
from social_core.backends.google import GoogleOAuth2
from social_core.backends.oauth import BaseOAuth2
#---------------------------------------------------------------------------------------------------------
from knox.views import LoginView as KnoxLoginView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.views import TokenObtainPairView
from knox.auth import AuthToken

#________________________________________________________________________________________________________________________
'''
def funct (request):
  template = loader.get_template('*.html')
  return HttpResponse(template.render())
def product(request):
    return render(request,'apps/app.html')
'''
from django.middleware import csrf
def my_view(request):
    csrf_token = csrf.get_token(request)
    return HttpResponse(csrf_token)
#""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
'''
_________________________________________________________________________________________________________________________________________________________________
  the esssentiel functionnaleties :
**************************************************************************************************************** 
1. Membership management:
****************************************************************************************************************
    * Allow users to request membership by join us as a member via creating a new dmd-inscript of type member
    * Approve/reject membership requests by admin (ie: add to db/delete from dmd-inscript table) --> trait dmd-inscript
    * Manage ('read,update,delete') elements from member profiles by the member profile owner 
    * Display list members  to the admin
    * Manage member directory by admin (affect roles,change the status of actif,delete,read,create,search,filter members,trait dmd-inscript)
    * create an account for the member if his request is accepted ie: once he is added to the member list by admin 
    * Authenticate members (login/logout)
    *change pasword
    * recieve notifications (in his profile/email) from the official mail of the association if:
       * his role is updated --> done
       * he is deleted from the members list --> done
       * if he is  accepted as a member or rejected from being a member
       * if he is added to a new organizers group of an event
*************************************************************************************************
3. Volunteer management:
****************************************************************************************************************
    * Allow visitors to request to become volunteers by join us as a volunteer and enter his informations via creating a new dmd-inscript of type benevole
    * Approve/reject volunteer requests by admin (ie: add to db/delete from dmd-inscript table) --> trait dmd-inscript
    * Display volunteers list to the admin
    * Manage volunteer data by admin (delete,read,create,search,filter volunteers,trait dmd-inscript)
    * recieve notifications (in his email) from the official mail of the association if:
      * if he is  accepted as a volunteer or rejected from being a volunteer
      * if he is added to the list of benevoles of certain event 
      * if there is an upcoming event to let(inform) him join  the event as volenteer
*************************************************************************************  
4. Partner management:
****************************************************************************************************************
    * Allow users to request partnership join us as a Partner via creating a new dmd-inscript of type Partner
    * Approve/reject partnership requests by admin (ie: add to db/delete from dmd-inscript table) --> trait dmd-inscript
    * Manage partner by admin (delete,read,create,search,filter,list Partners,trait dmd-inscript)
    * recieve notifications (in email) from the official mail of the association if:
      * if he is  accepted as a Partner or rejected from being a Partner
      * if he is added to the list of partenaires of certain event 
*******************************************************************************************************	  
5. Donation management:
    * Allow visitors to make donations for the association and become donators (they will be automatically added to the database (donators table))
    * Allow visitors to make donations for a certain event of his choice they will be automatically added to the database (donators table) and added to the list of donators for that event 
    - Process donations through ePay service "chargily"
    * View all donations donated history by the admin
    * Manage Donations by admin :
      *delete,read,create,search,filter dons and donators
      *update the necessary information (somme collecté once a new donation is added to a certain event)
    * recieve notifications (in his email) from the official mail of the association if:
      * to Confirm  his donations
****************************************************************************************
6. Event management:
    * Manage events data by admin :
     * delete,read,create,search,update,filter data of an event 
******************************************************************************************************       
7. Communication (messge,msg d'aide,dmd-inscript) management:
    * Allow visitors to contact the association via 
       * Messages (random (feedback given ,questions.....)
       * get help messages (to be added to msg aide )
       * demand inscriptions as member,volenteer,partner   
    * manage msg d'aide informations (delete,read,create (add to db),search,update,filter)
    * manage message random  informations (delete,read,create (add to db),search,update,filter)
    * Manage contact requests ( accept msg d'aide (ie add a Beneficiaire to db(Beneficiaire table)) ,refuse msg d'aide (delete from db (msg d'aide table)))
    * recieve emails by the visitor who contact us from the official mail of the association  :  
      * by  get help messages(msg aide)  if the beneficaaire requested in the message is accepted and added as a Beneficiaire in which event
_________________________________________________________________________________________________________________________________________________________________
'''
##################################################################################################	
#--------------------------------------------------------------------------------------------------------------------
# Members management
#--------------------------------------------------------------------------------------------------------------------
# member viewset :
#provides the CRUD (Create, Retrieve, Update, Delete) operations for your Member model
#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
class MemberViewSet(viewsets.ModelViewSet):

    queryset = models.Member.objects.all().order_by('date_iscript')
    # The default queryset of Member objects to be used for all operations
    serializer_class = MemberSerializer
    #The serializer class to be used for serializing and deserializing Member objects in requests and responses
    permission_classes = [permissions.AllowAny]
    #The permission classes to be used to control access to the view.
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    # The filter backends to be used for filtering and searching the queryset
    search_fields = ['Nom', 'Prenom', 'role', 'actif']
    #The fields to search for when using the search filter backend
    filterset_fields = ['Nom', 'Prenom', 'role', 'actif']
    #The fields to use for filtering when using the django-filter backend
    ordering_fields = ['date_iscript', 'Nom', 'role']
    #The fields to use for sorting when using the ordering filter backend
##################################################################################################
    def get_object(self):
        try:
            return models.Member.objects.get(id=self.kwargs['pk'])
        except models.Member.DoesNotExist:
            return(status.HTTP_404_NOT_FOUND)   
##################################################################################################
# update the role of a member  :
##################################
# (could be done only by admins)
class UpdateRoleViewSet(APIView):

    def post(self ,request, pk=None):
        new_role = request.data.get('new_role')
        member = models.Member.objects.get(id=pk)
        if member is not None and new_role in [choice[0] for choice in models.Role.choices]:
            role=member.role
            member.role=new_role 
            member.save()
            notify_updated_role(member=member,role=role,new_role=new_role)
            return Response({'message': 'role updated successfully'})
        else:
            return Response({'error': 'Invalid role value.'}, status=status.HTTP_400_BAD_REQUEST)        
###################################################################################################
# delete a member from the db 
###########################################
@api_view(['DELETE'])
@permission_classes([])
def delete_member(request, pk):
    try:
        member = models.Member.objects.get(pk=pk)
    except models.Member.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    
    member_deleted_handler(member) # inform the member that he is deleted
    member.delete()
    
    return Response(status=status.HTTP_204_NO_CONTENT)
#######################################################################################""
#--------------------------------------------------------------------------------
# login :
#----------------------------------------------------------------------------------
class LoginAPI(KnoxLoginView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request, *args, **kwargs):
        serializer = AuthTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        token, created = Token.objects.get_or_create(user=user)
        member = user.member  # Assumes the related name for the member model is "member"
        member_serializer = MemberSerializer(member)  # Use your own MemberSerializer
        return Response({
            'token': token.key,
            'member': member_serializer.data
        })   
#--------------------------------------------------------------------------------
# google_login :
#----------------------------------------------------------------------------------
class GoogleOAuth2Adapter(BaseOAuth2):
    """
    Google OAuth2 authentication backend
    """
    name = 'google-oauth2'
    access_token_url = 'https://oauth2.googleapis.com/token'
    authorize_url = 'https://accounts.google.com/o/oauth2/auth'
    profile_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    redirect_uri_protocol = 'https'
    SCOPE_SEPARATOR = ' '
    ID_KEY = 'sub'
    EXTRA_DATA = [
        ('name', 'name'),
        ('email', 'email'),
    ]
###############################################################################################################
    def complete_login(self, request, app, token, **kwargs):
        """
        Returns user data after successful login
        """
        # Get user data from the provider API
        headers = {'Authorization': 'Bearer ' + token.token}
        resp = self.request(self.profile_url, headers=headers)
        data = resp.json()

        # Extract the user details
        uid = data.get('id')
        name = data.get('name')
        email = data.get('email')

        # Check if the user with this email already exists in the database
        try:
            member = models.Member.objects.get(email=email)
            user = member.user
        except models.Member.DoesNotExist:
            # Create a new user and member object
            username = email.split('@')[0]
            password = User.objects.make_random_password()
            user = User.objects.create_user(username=username, email=email, password=password)
            member = models.Member.objects.create(user=user)
            '''
            # Associate the Google access token with the new user
            social_token = SocialToken.objects.create(
                user=user,
                provider=self.name,
                app=app,
                token=token.token,
            )
            ''' 
        # Log the user in to the app
        login(request, user)

        # Return a success response
        return JsonResponse({'message': 'Successfully logged in with Google.'})
###############################################################################################################
@api_view(['POST'])
@require_http_methods(['POST'])
def google_login(request):
    """
    Logs the user in with Google
    """
    try:
        # Load the Google OAuth2 backend
        backend = load_backend(load_strategy(request), 'google-oauth2', redirect_uri=None)

        # Authenticate the user with the access token
        user = backend.do_auth(request.data.get('access_token'))

        # If the user was successfully authenticated, return a response with a token and member info
        if user:
            token = user.social_auth.get(provider='google-oauth2').access_token
            serializer = MemberSerializer(user.member)
            return Response({'token': token, 'member_info': serializer.data})
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # Return an error response if authentication failed
    return Response({'error': 'Failed to authenticate with Google.'}, status=status.HTTP_400_BAD_REQUEST)
###################################################################################################
#--------------------------------------------------------------------------------------------------------------------
# logout
#-------------------------------------------------------------------------------------
@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def logout_view(request):
    # Log the user out
    logout(request)
    # Return a success response
    return Response({'detail': 'User  Logout successfully.'})
# ------------------------------------------------------------------------------------------------- 
################################################################################################### 
#---------------------------------------------------------------------------------------
# change password
# ------------------------------------------------------------------------------------------------- 
class ChangePasswordView(APIView):
    
    def post(self, request, pk=None):
        old_pass =request.data.get('old_pass')
        new_pass = request.data.get('new_pass')
        member = models.Member.objects.get(id=pk)
        user = member.user
        if user is not None and user.check_password(old_pass) :
            user.set_password(new_pass)
            user.save()
            member.user = user
            member.save()
            return Response({'message': 'Password changed successfully for the user'})
        else:
            return Response({'message': 'User with that username does not exist'}, status=400)
#---------------------------------------------------------------------------------------
# change username
# -------------------------------------------------------------------------------------------------         
class ChangeUsernameView(APIView):
    
    def post(self, request, pk=None):
        new_username = request.data.get('new_username')
        member = models.Member.objects.get(id=pk)
        user = member.user
        if user is not None :
            user.username=new_username
            user.save()
            member.user = user
            member.save()
            return Response({'message': 'Username changed successfully for the user'})
        else:
            return Response({'message': 'User with that username does not exist'}, status=400)
#----------------------------------------------------------------------------------------------
# change email
#-------------------------------------------------------------------------------------------------------
class ChangeEmailView(APIView):
    
    def post(self, request, pk=None):
        new_email= request.data.get('new_email')
        member = models.Member.objects.get(id=pk)
        user = member.user
        if user is not None :
            user.email=new_email
            user.save()
            member.user = user
            member.save()
            return Response({'message': 'email changed successfully for the user'})
        else:
            return Response({'message': 'error'}, status=400)


#--------------------------------------------------------------------------------------------------------------------
# Events management
#--------------------------------------------------------------------------------------------------------------------
def total_amount_collected(request):
        total_amount = models.Event.calculate_total_amount_collected()
        total_amount = round(total_amount, 2) 
        return JsonResponse({'total_amount_collected': total_amount})
#--------------------------------------------------------------------------------------------------------------------
def total_number_benef(request):
        total_benef = models.Event.calculate_total_benef_list()
        return JsonResponse({'total_number_benef': total_benef})
#--------------------------------------------------------------------------------------------------------------------
def total_number_event(request):
        total_event = models.Event.calculate_total_event_list()
        return JsonResponse({'total_number_event': total_event})   
#--------------------------------------------------------------------------------------------------------------------
def total_number_member(request):
        total_member = models.Member.calculate_total_member_list()
        return JsonResponse({'total_number_member': total_member})
#------------------------------------------------------------------------------------------------------------------
def statistics_event(request, event_id):
    event = get_object_or_404(models.Event, id=event_id)
    
    if event.donation_goal == 0 or event.donation_goal is None :
        proportion = 0
    else:
        proportion = (event.somm_collect * 100) / event.donation_goal
        proportion = round(proportion, 2) 
    return JsonResponse({'proportion': proportion})
# -----------------------------------------------------------------------------------------
@api_view(['GET'])
def get_member_events(request, pk):
    member = models.Member.objects.get(id=pk)
    events = models.Event.objects.filter(Q(equipe=member) | Q(chef_equipe=member))
    serializer = EventSerializer(events, many=True)
    return Response(serializer.data)
#-----------------------------------------------------------------------------------
class VideoViewSet(viewsets.ModelViewSet):
    queryset = models.Video.objects.all()
    serializer_class = serializers.VideoSerializer
    permission_classes = [permissions.AllowAny] 
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    search_fields = ['filename', 'created_at','updated_at','video_file']
    ordering_fields = ['filename', 'created_at', 'updated_at']
#--------------------------------------------------------------------------------------------------------------------
class imgViewSet(viewsets.ModelViewSet):
    queryset = models.img.objects.all()
    serializer_class = serializers.imgSerializer
    permission_classes = [permissions.AllowAny] 
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    search_fields = ['filename', 'created_at','updated_at','image']
    ordering_fields = ['filename', 'created_at', 'updated_at']
#--------------------------------------------------------------------------------------------------------------------
class EventViewSet(viewsets.ModelViewSet):
    queryset = models.Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [permissions.AllowAny] 
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    search_fields = ['titre', 'date_début','date_fin','lieu','donation_goal','chef_equipe','partenaires']
    ordering_fields = ['date_début', 'date_fin', '-donation_goal']
    #-----------------------------------------------------------------------------------------------
    
######################################################################
# adding the the lists
####################################################################    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        # Custom logic for updating the view
        updated_instance = serializer.instance
        # Perform any additional operations or modifications to the instance 
        #--------------------------------------------------------
        benevole_list = updated_instance.benevole_list.all()
        for benevole in benevole_list:          
          notify_volenteer_join(benevole,instance)
        #-------------------------------------------------------- 
        partenaires = updated_instance.partenaires.all()
        for partenaire in partenaires:
           notify_partner(partenaire,instance)
        #--------------------------------------------------------
        beneficiaires=updated_instance.benef_list.all()
        for benef in beneficiaires:
            b=models.Beneficiaire.objects.get(id=benef.id)
            b.nb_ben=+1
            b.save()
        #--------------------------------------------------------
        membre_equipe = updated_instance.equipe.all()
        for membre in membre_equipe:
           notify_members_join(membre,instance)
           m=models.Member.objects.get(id=membre.id)
           role=m.role
           m.role=models.Role.ORGANISATEUR.value
           notify_updated_role(m,role,m.role)
           m.actif=True
           m.save()
        #--------------------------------------------------------
        self.perform_update(serializer)
        return Response(self.get_serializer(updated_instance).data)
    #----------------------------------------------------------------------------
    def perform_create(self, serializer):
        new_event = serializer.save()
        # Get all the volunteers
        volunteers = models.Benevole.objects.all()
        # Send email to each volunteer
        for volunteer in volunteers:
           notify_volenteer_join(volunteer, new_event) 

        members = models.Member.objects.all()
        # Send email to each volunteer
        for member in members:
            notify_members_join(member, new_event)

######################################################################################################### 
#  display lists
#############################################################
    @action(detail=True, methods=['get'])
    def beneficiaires_list(self, request, pk=None):
        try:
            event = self.get_object()
        except models.Event.DoesNotExist:
            return Response(status=404)

        beneficiaires = event.benef_list.all()
        serializer = BeneficiaireSerializer(beneficiaires, many=True)
        return Response(serializer.data)
####################################################################################
    @action(detail=True, methods=['get'])
    def partenaires_list(self, request, pk=None):
        try:
            event = self.get_object()
        except models.Event.DoesNotExist:
            return Response(status=404)

        partners = event.partenaires.all()
        serializer = PartenaireSerializer(partners, many=True)
        return Response(serializer.data)
##################################################################################
    @action(detail=True, methods=['get'])
    def benevole_list(self, request, pk=None):
        try:
            event = self.get_object()
        except models.Event.DoesNotExist:
            return Response(status=404)

        benevoles = event.benevole_list.all()
        serializer = BenevoleSerializer(benevoles, many=True)
        return Response(serializer.data)

########################################################################################
    @action(detail=True, methods=['get'])
    def equipe(self, request, pk=None):
        try:
            event = self.get_object()
        except models.Event.DoesNotExist:
            return Response(status=404)

        equipe= event.equipe.all()
        serializer = MemberSerializer(equipe, many=True)
        return Response(serializer.data)
##############################################################################################   
# lister toutes les donation associées a un event
#####################################################################################
@api_view(['GET'])
def event_donations(request, event_id):
    try:
       donations = models.Donation.objects.filter(id=event_id)
       serialized_donations = DonationSerializer(donations, many=True)
       return Response(serialized_donations.data, status=status.HTTP_200_OK)
    except models.Donation.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
#--------------------------------------------------------------------------------------------------------------------
# creating notifications and sending emails management
#--------------------------------------------------------------------------------------------------------------------
############################################################################################## 
# lister toutes les notifications associées au membre
#####################################################################################  
@api_view(['GET'])
def list_notifications(request, member_id):
    try:
        notifications = models.Notification.objects.filter(recepteur__id=member_id)
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except models.Notification.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
#===============================================================================================
# notification of accepting  a membership request by adding the demandeur to the db as a member
#===============================================================================================
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def send_member_accept_notif(new_member,password):
    # the demandeur is already added to the db he is now a new member
    # create a notification for the demandeur (new member) 
    notification = models.Notification.objects.create(
        contenu='Your membership request has been accepted',
        recepteur=new_member,
        date_envoi=timezone.now(),
        type=models.NotificationType.ACCEPTANCE,
    )
    notification.save()
    # send email to notify the new_member about his new account
    subject = 'Membership request is accepted'
    recipient_list = [new_member.user.email]
    context = {
        'new_member': new_member,
        'password': password,
    }
    html_message = render_to_string('member_accepted.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)
    
#======================================================================================================
# accept volenteer request  by adding the new benevole to the db
#====================================================================================================== 
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def send_volenteer_accept_notif(volunteer):
    subject = 'Volunteer Request Accepted'
    recipient_list = [volunteer.email]
    context = {
        'volunteer': volunteer,
    }
    html_message = render_to_string('benevole_accepted.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)
    
#=======================================================================================================================
# reject inscription request (as : member,volenteer,partner) notification by deleting the dmd inscript of the demandeur
#=======================================================================================================================
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def send_demand_deleted_notification(demand,email):
    subject = 'Join request rejected'
    recipient_list = [email]
    context = {
        'demand': demand,
    } 
    html_message = render_to_string('demand_rejected.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)   
#============================================================================
# accept partner request notification by adding the new partner to the db
#==========================================================================================
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def send_partner_accepted_notification(partner):
    subject = 'Partnership request accepted'
    recipient_list = [partner.email]
    context = {
        'partner': partner,
    }                      
    html_message = render_to_string('partner_acepted.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)
 
#==========================================================================================
# member deleted from the db notification
#==========================================================================================
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def member_deleted_handler( member):
    # if a member is deleted from db no need to create a notification and add it to his notif cuz,his already deleted
    # directly we send an email to notify the deleted member
    subject = 'Member removed'
    recipient_list = [member.user.email]
    context = {
        'member': member,
    }
    html_message = render_to_string('member_deleted.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)
#==========================================================================================
#  notify volenteer added to a  benvoles list  of an event 
#==========================================================================================
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def notify_volenteer(benevole, Event):
    subject = 'You are a part of our event'
    recipient_list = [benevole.email]
    context = {
        'benevole':benevole,
        'Event':Event,
    }
    html_message = render_to_string('added_to_benevlist.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)

#==========================================================================================
#  notify volenteer  to join a new event created in the siteto be part of its volenteers
#========================================================================================== 
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def notify_volenteer_join(benevole, Event):
    subject = 'New event is coming'
    recipient_list = [benevole.email]
    context = {
        'benevole':benevole,
        'Event':Event,
    }

    html_message = render_to_string('join_benev.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)
 
#==========================================================================================
#  notify all members  to join a new event created in the site to be part of its organizers
#========================================================================================== 
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags   
def notify_members_join(member, new_event):

    notification = models.Notification.objects.create(
        contenu='New event is coming',
        recepteur=member,
        date_envoi=timezone.now(),
        type=models.NotificationType.ACCEPTANCE,
    )
    notification.save()
    subject = 'New event is coming'
    recipient_list = [member.user.email]
    context = {
        'member':member,
        'new_event':new_event,
    }
    html_message = render_to_string('join_equipe.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)

    
           
#==========================================================================================
#  notify partner added to a  partenaires list  of an event 
#==========================================================================================
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def notify_partner(partner, Event):
    subject = 'Partner for our new event'
    recipient_list = [partner.email]
    context = {
        'partner':partner,
        'Event':Event,
    }
    html_message = render_to_string('added_to_partnerlist.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)
#==========================================================================================
#  notify member added to a new organizers group of an event 
#==========================================================================================
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def notify_organizer(member, Event):
   # if ((member.role == models.Member.Role.RESPENSABLE_EVENT) |(member.role == models.Member.Role.ORGANISATEUR)):
    notification =models.Notification.objects.create(
        recipient=member,
        contenu=f"You have been added to the organizers group of {Event.titre} as {member.role}",
        date_envoi=timezone.now(),
        type=models.NotificationType.ROLE_UPDATED,
       # target=Event,
                ) 
    notification.save()
    subject = 'new organizers team '
    recipient_list = [member.user.email]
    context = {
        'member':member,
        'Event':Event,
    }
    html_message = render_to_string('added_to_org.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)
#==========================================================================================
#  notify member if his role is updated 
#==========================================================================================
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def notify_updated_role(member,role,new_role):   
    notif=models.Notification.objects.create(
        recepteur=member,
        contenu=f"Your role is updated you are now {new_role}",
        date_envoi=timezone.now(),
        type=models.NotificationType.ROLE_UPDATED,
                )
    notif.save()
    subject = 'Your role is updated'
    recipient_list = [member.user.email]
    context = {
        'member':member,
        'role':role,
        'new_role':new_role,
    }
    html_message = render_to_string('updated_role.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)

#===============================================================================================
# notification of accepting  a help request by adding the demandeur to the db as a beneficiaire
#===============================================================================================
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def send_helpmsg_accept_notif(beneficiaire): 
    subject = 'get help request accepted'
    recipient_list = [beneficiaire.email]
    context = {
        'beneficiaire':beneficiaire,
    }
    html_message = render_to_string('accept_help_msg.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)

#===============================================================================================
# notification to confirm the donation type don_argent of donateur 
#===============================================================================================
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags 

def send_confirm_don_argent_notif(donateur,donation):
    subject = 'Donation confirmation'
    recipient_list = [donateur.email]
    context = {
        'donateur':donateur,
        'donation':donation,
    }  
    html_message = render_to_string('confirm_don_argent.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)
#===============================================================================================
# notification to confirm the donation type don_choses of donateur 
#===============================================================================================
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags 

def send_confirm_don_choses_notif(donateur,donation):
    subject = 'Donation confirmation'
    recipient_list = [donateur.email]
    context = {
        'donateur':donateur,
        'donation':donation,
    }  
    html_message = render_to_string('confirm_don_choses.html', context)
    plain_message = strip_tags(html_message)

    email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, recipient_list)
    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)

#####################################################################################################################
class NotificationViewSet(viewsets.ModelViewSet):
    # list create delete read notif
    queryset = models.Notification.objects.all().order_by('date_envoi')
    serializer_class = NotificationSerializer
    permission_classes = [permissions.AllowAny]
    ordering_fields = ['date_envoi', 'is_checked']      
###################################################################################################  
#--------------------------------------------------------------------------------------------------------------------    
#  pertners management :
#--------------------------------------------------------------------------------------------------------------------
class PartenaireViewSet(viewsets.ModelViewSet):
    queryset = models.Partenaire.objects.all().order_by('-Date_collab')
    serializer_class = PartenaireSerializer
    permission_classes = [permissions.AllowAny] 
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['Nom_org', 'Date_collab','email']
    ordering_fields = ['Date_collab']
###################################################################################################
#--------------------------------------------------------------------------------------------------------------------    
#  Dmd_Inscription management :
#--------------------------------------------------------------------------------------------------------------------
# s'inscrire dans l'association: "join us" 
class Dmd_InscriptionViewSet(viewsets.ModelViewSet):
    queryset = models.Dmd_inscript.objects.all().order_by('-date_dmd')
    serializer_class = serializers.Dmd_inscriptSerializer
    permission_classes = [permissions.AllowAny] 
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    search_fields = ['type', 'statut_dmd','demandeur']
    ordering_fields = ['date_dmd']

###################################################################################################################################################
# reject the dmd_inscript (delete it)
#############################################################################################################################################
@api_view(['POST'])
@transaction.atomic
def refuse(request, pk):
    try:
        dmd = models.Dmd_inscript.objects.get(pk=pk)
        send_demand_deleted_notification(dmd.demandeur,dmd.email)
        dmd.delete()
        return Response({'message': 'Demande refusée et supprimée avec succès!'})
    except models.Dmd_inscript.DoesNotExist:
        return Response({'message': 'La demande n\'existe pas'}, status=status.HTTP_404_NOT_FOUND)   
################################################################################################
# accept the dmd_inscript
################################################################################################
#(could be done only by admins)
@api_view(['POST'])   
@transaction.atomic
def accept(request, pk=None):
    try:
        dmd = models.Dmd_inscript.objects.get(id=pk)
    except models.Dmd_inscript.DoesNotExist:
        return Response({'error': 'Demande not found.'}, status=status.HTTP_404_NOT_FOUND)
    #-----------------------------------------------------------------------------------------------
    if dmd.type == 'M':
            # add a demandeur as a member to db  ie: his membership (join_us as a member) is accepted 
            username = f"{dmd.demandeur.Nom}{dmd.demandeur.Prenom}"
            password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(5))

            user=User.objects.create_user(
                    username=username,
                    password=password,
                    email=dmd.email
            )
            member = models.Member.objects.create(
                user=user,
                Nom=dmd.demandeur.Nom,
                Prenom=dmd.demandeur.Prenom,
                Age=dmd.demandeur.Age,
                Date_Naissance=dmd.demandeur.Date_Naissance,
                Adresse=dmd.demandeur.Adresse,
                Num_tel=dmd.demandeur.Num_tel,
                Sexe=dmd.demandeur.Sexe,
                Pays=dmd.demandeur.Pays,
                date_iscript=timezone.now(),
                photo_profil=None,
                actif=False,
                role=models.Role.MEMBER.value,
            )
            member.save()
            user.save()
            send_member_accept_notif(member,password)
    
    elif dmd.type == 'P':
        p = models.Partenaire.objects.create(
                respo_partner=dmd.demandeur,
                email=dmd.email,
                Nom_org=dmd.Nom_org,
                Descript_org=dmd.motivation,
                logo=None,
                Date_collab=timezone.now(),
            )
        p.save()
        send_partner_accepted_notification(p)

    elif dmd.type == 'B':
         benevole = models.Benevole(
             #actor:
                Nom=dmd.demandeur.Nom,
                Prenom=dmd.demandeur.Prenom,
                Age=dmd.demandeur.Age,
                Date_Naissance=dmd.demandeur.Date_Naissance,
                Adresse=dmd.demandeur.Adresse,
                Num_tel=dmd.demandeur.Num_tel,
                Sexe=dmd.demandeur.Sexe,
                Pays=dmd.demandeur.Pays,
                email=dmd.email,
                Date_inscript=timezone.now(),
                bénévolat=dmd.motivation,
            )
         benevole.save()
         send_volenteer_accept_notif(benevole)

    dmd.statut_dmd = True
    dmd.save()
    #dmd.delete()
    return Response({'success': 'Demande has been accepted.'}, status=status.HTTP_200_OK)
################################################################################################       
#--------------------------------------------------------------------------------------------------------------------    
#  Msg_aide management :
#--------------------------------------------------------------------------------------------------------------------
class Msg_aideViewSet(viewsets.ModelViewSet):
    queryset = models.Msg_aide.objects.all()
    serializer_class = serializers.Msg_aideSerializer
    permission_classes = [permissions.AllowAny] 
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    search_fields = ['Statut_msg','benefic_info']
    ordering_fields = ['date_ben','sit_sociale']

    def get_queryset(self):
        queryset = models.Msg_aide.objects.all()

        # Order the queryset based on sit_sociale_priority using Python's sorted function
        queryset = sorted(queryset, key=lambda x: self.get_sit_sociale_priority(x.sit_sociale))

        return queryset

    def get_sit_sociale_priority(self, sit_sociale):
        SIT_SOCIALE_PRIORITY = {
            'victime_catastrophe_nat': 1,
            'hospitalisé': 2,
            'malade': 3,
            'sans_abri': 4,
            'pauvre': 5,
            'handicapé': 7,
            'cancéreux': 8,
            'orphelin': 9,
            'autiste': 10,
            'sans_etude': 11,
            'eleve': 12,
            'veuve': 13,
            'besoin_particulier': 14,
        }
        return SIT_SOCIALE_PRIORITY.get(sit_sociale, 0)
################################################################################################  
#  accept demande d'aide
#######################################################################    
@api_view(['POST'])  
def accept_help_benef(request, pk=None):
    try:
        m = models.Msg_aide.objects.get(id=pk)

    except models.Msg_aide.DoesNotExist:
        return Response({'error': 'Demande not found.'}, status=status.HTTP_404_NOT_FOUND) 

    
    ben = models.Beneficiaire.objects.create(
                sit_sociale=m.sit_sociale,
                date_ben=timezone.now(),
                nb_ben=0,
                email=m.sender_email,
                Age=m.benefic_info.Age,
                Prenom=m.benefic_info.Prenom,
                Nom=m.benefic_info.Nom,
                Date_Naissance=m.benefic_info.Date_Naissance,
                Adresse=m.benefic_info.Adresse,
                Num_tel=m.benefic_info.Num_tel,   
                Sexe=m.benefic_info.Sexe,
                Pays=m.benefic_info.Pays,
            )
    m.Statut_msg = True
    m.save()
    ben.save()
    send_helpmsg_accept_notif(ben)
    return Response({'success': 'Demande has been accepted.'}, status=status.HTTP_200_OK)

#--------------------------------------------------------------------------------------------------------------------    
#  Message management :
#--------------------------------------------------------------------------------------------------------------------
class MessageViewSet(viewsets.ModelViewSet):
    queryset = models.Message.objects.all().order_by('date_envoie')
    serializer_class = serializers.MessageSerializer
    permission_classes = [permissions.AllowAny]  
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    search_fields = ['Statut_msg','type']
    ordering_fields = ['date_envoie']
################################################################################################    
    def get_queryset(self):
        queryset=models.Message.objects.all()
        return queryset
################################################################################################   
#--------------------------------------------------------------------------------------------------------------------    
#  Donateur management :
#--------------------------------------------------------------------------------------------------------------------
class DonateurViewSet(viewsets.ModelViewSet):
    queryset = models.Donateur.objects.all()
    serializer_class = serializers.DonateurSerializer
    permission_classes = [permissions.AllowAny] 
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    search_fields = ['Nom', 'Prenom','numero_carte','Pays','Email','Num_tel','type_don']
    ordering_fields = ['date_donation']

################################################################################################
#--------------------------------------------------------------------------------------------------------------------    
#  Dons management :
#--------------------------------------------------------------------------------------------------------------------
class Don_chosesViewSet(viewsets.ModelViewSet):
  queryset = models.Don_choses.objects.all().order_by('date_donation')
  serializer_class = serializers.Don_chosesSerializer
  permission_classes = [permissions.AllowAny]
  filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
  search_fields = ['donateur', 'type_don','date_donation','Qte','item']
  ordering_fields = ['date_donation','-Qte']

  def create(self, request, *args, **kwargs):
    serializer = self.get_serializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    donateur_data = serializer.validated_data.get('donateur')
    donateur = None
    if donateur_data:
        donateur_serializer = serializers.DonateurSerializer(data=donateur_data)
        donateur_serializer.is_valid(raise_exception=True)
        donateur = donateur_serializer.save()

    item_name = serializer.validated_data.get('item')
    qte = serializer.validated_data.get('Qte')

    item = None
    if item_name:
        item, created = models.Item.objects.get_or_create(item=item_name, defaults={'Qte': qte})
        if not created:
            item.Qte += qte
            item.save()

    validated_data = serializer.validated_data.copy()
    validated_data.pop('donateur')
    validated_data['item'] = item_name or ''  # Set default value as an empty string
    don_choses = models.Don_choses(**validated_data, donateur=donateur)
    don_choses.save()
    send_confirm_don_choses_notif(donateur,don_choses)
    
    return Response(serializer.data, status=status.HTTP_201_CREATED)
   

'''

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        donateur_data = serializer.validated_data.get('donateur')
        donateur = None
        if donateur_data:
            donateur_serializer = serializers.DonateurSerializer(data=donateur_data)
            donateur_serializer.is_valid(raise_exception=True)
            donateur = donateur_serializer.save()

        validated_data = serializer.validated_data.copy()
        validated_data.pop('donateur')
        validated_data.pop('item')
        validated_data.pop('Qte')
        #don_choses = models.Don_choses(**validated_data, donateur=donateur)
        #don_choses.save()
        it, created = models.Item.objects.get_or_create(item=item)
        if created:
         item.Qte = Qte
        else:
         item.Qte += Qte
        item.save()
        don_choses = models.Don_choses(**serializer.validated_data)
        don_choses.save()

     
        item = models.Item.objects.get_or_create(item=item_name)
        if item is not None:
            item.Qte += qte
            item.save()
        else :
          item=models.Item.objects.create(item=item_name,Qte=qte)
          item.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
 '''   '''
    def perform_create(self, serializer):
        don_choses_instance = serializer.save()
        donateur = don_choses_instance.donateur
        # Call the function to send email confirmation
        send_confirm_don_notif(donateur)
    ''' 
################################################################################################
def item_list(request):
    items = models.Item.objects.all()
    return render(request, 'item_list.html', {'items': items})
################################################################################################
class ItemListAPIView(viewsets.ModelViewSet):
    queryset = models.Item.objects.all().order_by('Qte')
    serializer_class = ItemSerializer
    permission_classes = [permissions.AllowAny]

################################################################################################
class Don_argentViewSet(viewsets.ModelViewSet):
    queryset = models.Don_argent.objects.all().order_by('date_donation')
    serializer_class = serializers.Don_argentSerializer
    permission_classes = [permissions.AllowAny]
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    search_fields = ['donateur', 'type_don','date_donation','mode_paiement','montant']
    ordering_fields = ['date_donation','-montant']
#=================================================================================================================
# ajouter don argent
#======================================================================================
    @transaction.atomic
    def perform_create(self, serializer):
        don_argent_instance = serializer.save()
        donateur = don_argent_instance.donateur

        '''
        # Process the donation via Chargily's epay service
        url = 'http://epay.chargily.com.dz/api/invoice'
        secret_key = settings.CHARGILY_SECRET_KEY
        headers = {'X-Authorization': secret_key, 'Accept': 'application/json'}
        payload = {
            'client': donateur.Nom,
            'client_email': donateur.email,
            'invoice_number': str(don_argent_instance.id),
            'amount': don_argent_instance.montant,
            'discount': 0,
            'back_url': 'http://your-website.com/back-url',
            'webhook_url': 'http://your-website.com/webhook-url',
            'mode': 'EDAHABIA',
            'currency': 'DZD',
            'description': f'Donation for event {don_argent_instance.event.titre}' if don_argent_instance.event.id else 'Free donation',
        }
        response = requests.post(url, headers=headers, data=payload)
        
        #return Response({'success': True})
        if response.status_code == status.HTTP_201_CREATED:
            # If the donation was successfully processed, return a success response
            
            don_argent_instance.event.somm_collect += don_argent_instance.montant
            don_argent_instance.event.save()
            # Send confirmation email to donor
            send_confirm_don_argent_notif(donateur,don_argent_instance)
            # If the donation was successfully created, retrieve the checkout URL and redirect the user
            checkout_url = response.json().get('checkout_url')
            return Response({'checkout_url': checkout_url})  
        else:
            # If there was an error creating the donation, return an error response
            error_msg = response.json().get('detail', 'Unknown error')
            return Response({'error': error_msg}, status=status.HTTP_400_BAD_REQUEST)
            '''
        # Call the function to send email confirmation
        send_confirm_don_argent_notif(donateur,don_argent_instance)
        don_argent_instance.event.somm_collect += don_argent_instance.montant
        don_argent_instance.event.save()
################################################################################################
#--------------------------------------------------------------------------------------------------------------------    
#  Donation management :
#--------------------------------------------------------------------------------------------------------------------
class DonationViewSet(viewsets.ModelViewSet):
    queryset = models.Donation.objects.all()
    serializer_class = serializers.DonationSerializer
    permission_classes = [permissions.AllowAny] 
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    search_fields = ['type_don', 'date_donation','donateur','event']
    ordering_fields = ['date_donation'] 
################################################################################################
class DonViewSet(viewsets.ModelViewSet):
    queryset = models.Don.objects.all().order_by('date_donation')
    serializer_class = serializers.DonSerializer
    permission_classes = [permissions.AllowAny]
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    search_fields = ['donateur', 'type_don','date_donation','event']
    ordering_fields = ['date_donation',]
################################################################################################              
#--------------------------------------------------------------------------------------------------------------------    
#  Benevole management :
#--------------------------------------------------------------------------------------------------------------------
class BenevoleViewSet(viewsets.ModelViewSet):
    queryset = models.Benevole.objects.all().order_by('Date_inscript')
    serializer_class = serializers.BenevoleSerializer
    permission_classes = [permissions.AllowAny] 
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    search_fields = ['Nom', 'Prenom','Date_inscript','bénévolat'] 
#--------------------------------------------------------------------------------------------------------------------    
#  Beneficiaire management :
#--------------------------------------------------------------------------------------------------------------------
class BeneficiaireListView(generics.ListAPIView):
    queryset = models.Beneficiaire.objects.all()
    serializer_class = serializers.BeneficiaireSerializer
    permission_classes = [permissions.AllowAny]
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    search_fields = ['Nom', 'Prenom', 'date_ben', 'nb_ben', 'sit_sociale']
    ordering_fields = ['date_ben']

    def get_queryset(self):
        queryset = models.Beneficiaire.objects.all()
        # Order the queryset based on sit_sociale_priority using Python's sorted function
        queryset = sorted(queryset, key=lambda x: self.get_sit_sociale_priority(x.sit_sociale))
        return queryset

    def get_sit_sociale_priority(self, sit_sociale):
        SIT_SOCIALE_PRIORITY = {
            'victime_catastrophe_nat': 1,
            'hospitalisé': 2,
            'malade': 3,
            'sans_abri': 4,
            'pauvre': 5,
            'handicapé': 7,
            'cancéreux': 8,
            'orphelin': 9,
            'autiste': 10,
            'sans_etude': 11,
            'eleve': 12,
            'veuve': 13,
            'besoin_particulier': 14,
        }
        return SIT_SOCIALE_PRIORITY.get(sit_sociale, 0)


class BeneficiaireDetailView(generics.RetrieveAPIView):
    queryset = models.Beneficiaire.objects.all()
    serializer_class = serializers.BeneficiaireSerializer
    permission_classes = [permissions.AllowAny]

    def get_sit_sociale_priority(self, sit_sociale):
        SIT_SOCIALE_PRIORITY = {
            'victime_catastrophe_nat': 1,
            'hospitalisé': 2,
            'malade': 3,
            'sans_abri': 4,
            'pauvre': 5,
            'handicapé': 7,
            'cancéreux': 8,
            'orphelin': 9,
            'autiste': 10,
            'sans_etude': 11,
            'eleve': 12,
            'veuve': 13,
            'besoin_particulier': 14,
        }
        return SIT_SOCIALE_PRIORITY.get(sit_sociale, 0)

#----------------------------------------------------------------------------------------
class BeneficiaireUpdateView(generics.UpdateAPIView):
    queryset = models.Beneficiaire.objects.all()
    serializer_class = serializers.BeneficiaireSerializer
    permission_classes = [permissions.AllowAny]


class BeneficiaireDeleteView(generics.DestroyAPIView):
    queryset = models.Beneficiaire.objects.all()
    serializer_class = serializers.BeneficiaireSerializer
    permission_classes = [permissions.AllowAny]
#---------------------------------------------------------------------------------------------------
class BeneficiaireViewSet(viewsets.ModelViewSet):
    queryset = models.Beneficiaire.objects.all()
    serializer_class = serializers.BeneficiaireSerializer
    permission_classes = [permissions.AllowAny]
    filter_backends = [filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter]
    search_fields = ['Nom', 'Prenom', 'date_ben', 'nb_ben', 'sit_sociale']
    ordering_fields = ['date_ben']

    def get_queryset(self):
        queryset = models.Beneficiaire.objects.all()
        # Order the queryset based on sit_sociale_priority using Python's sorted function
        queryset = sorted(queryset, key=lambda x: self.get_sit_sociale_priority(x.sit_sociale))
        return queryset

    def get_sit_sociale_priority(self, sit_sociale):
        SIT_SOCIALE_PRIORITY = {
            'victime_catastrophe_nat': 1,
            'hospitalisé': 2,
            'malade': 3,
            'sans_abri': 4,
            'pauvre': 5,
            'handicapé': 7,
            'cancéreux': 8,
            'orphelin': 9,
            'autiste': 10,
            'sans_etude': 11,
            'eleve': 12,
            'veuve': 13,
            'besoin_particulier': 14,
        }
        return SIT_SOCIALE_PRIORITY.get(sit_sociale, 0)



 

    


