from django.urls import path,include
from . import views
from .views import MemberViewSet,NotificationViewSet,PartenaireViewSet,EventViewSet,VideoViewSet,imgViewSet
from rest_framework import routers
from django.contrib.auth import views as auth_views
from knox import views as knox_views
from django.contrib.auth.views import PasswordChangeView, PasswordChangeDoneView
from django.contrib.auth.views import LogoutView


#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
router = routers.DefaultRouter()
#**********************************************************************
router.register(r'members', MemberViewSet, basename='member')
'''
urls:
/members/ # POST,GET
/members/{pk}/ # DELETE,PUT,GET 
/members/{pk}/update_role/ 
'''
#**********************************************************************
router.register(r'notifications', views.NotificationViewSet, basename='notification')
'''
/notifications/  # POST,GET 
/notifications/<pk>/ # DELETE ,PUT,GET 
'''
#**********************************************************************
router.register(r'partenaires', PartenaireViewSet, basename='Partenaire')
'''
/partenaires/ # POST,GET 
/partenaires/{pk}/ # DELETE ,PUT,GET
'''
#**********************************************************************
router.register(r'events', EventViewSet, basename='Event')
router.register(r'videos', VideoViewSet, basename='Video')
router.register(r'images', imgViewSet, basename='Image')
'''
GET POST/events/
GET,PUT, DELETE /events/{pk}/

GET POST/videos/
GET,PUT, DELETE /videos/{pk}/

GET POST/images/
GET,PUT, DELETE /images/{pk}/
'''
#**********************************************************************
router.register(r'dmd_inscription', views.Dmd_InscriptionViewSet)
'''
/dmd-inscription/ # POST,GET
/dmd-inscription/{pk}/ # DELETE ,PUT,GET
/dmd_inscriptions/{pk}/accept/ #POST 
/dmd_inscriptions/{pk}/refuse/ #POST
'''
#**********************************************************************
router.register(r'donateurs', views.DonateurViewSet, basename='Donateur')
router.register(r'don_choses', views.Don_chosesViewSet, basename='Don_choses')
router.register(r'don_argent', views.Don_argentViewSet, basename='Don_argent')
router.register(r'donations', views.DonationViewSet, basename='Donation')
router.register(r'dons', views.DonViewSet, basename='Don')
router.register(r'items', views.ItemListAPIView, basename='Item')
'''
/donateurs/ # POST,GET
/donateurs/<pk>/ # DELETE ,PUT,GET

/don_choses/ # POST,GET
/don_choses/<pk>/ # DELETE ,PUT,GET

/don_argent/ # POST,GET
/don_argent/<pk>/ # DELETE ,PUT,GET

/donations/ # POST,GET
/donations/<pk>/ # DELETE ,PUT,GET

/dons/ # POST,GET
/dons/<pk>/ # DELETE ,PUT,GET
'''
#**********************************************************************
router.register(r'msg_aide', views.Msg_aideViewSet, basename='Msg_aide')
'''
/msg-aide/ # POST,GET
/msg-aide/{pk}/ # DELETE ,PUT,GET
/msg-aide/{pk}/create_from_msg_aide/ # POST
'''
#**********************************************************************
router.register(r'message', views.MessageViewSet, basename='Message')
'''
/message/ # POST,GET
/message/{pk}/ # DELETE ,PUT,GET
'''
#**********************************************************************
# router.register(r'Beneficiaire', views.BeneficiaireViewSet, basename='Beneficiaire')
'''
/Beneficiaire/ # POST,GET
/Beneficiaire/{pk}/ # DELETE ,PUT,GET
'''
#**********************************************************************
router.register(r'benevoles', views.BenevoleViewSet, basename='Benevole')
'''
/benevoles/ # POST,GET
/benevoles/{pk}/ # DELETE ,PUT,GET
'''
#**********************************************************************
urlpatterns = [
    #--------------------------------------------------------------------------------------------------
    # routers for views of  CRUD operations  
    #--------------------------------------------------------------------------------------------------
    path('', include(router.urls)),
    #--------------------------------------------------------------------------------------------------
    # extra paths of api login/logout
    #--------------------------------------------------------------------------------------------------
    path('login/', views.LoginAPI.as_view(), name='login'),
    path('logout/', views.logout_view, name='logout'),
    #path('logout_view/', LogoutView.as_view(next_page='/'), name='logout'),    
    path('google_login/', views.google_login),
    #-------------------------------------------------------------------------------------
    #extra path of dmd_inscript
    #------------------------------------------------------------------------------------------------
    path('dmd_inscription/accept/<int:pk>/',views.accept,name='accept'),
    path('dmd_inscription/refuse/<int:pk>/',views.refuse,name='refuse'),
    #-----------------------------------------------------
    # extra urls for members
    #--------------------------------------------------------
    path('update_role/<int:pk>/', views.UpdateRoleViewSet.as_view(), name='update_role'),
    path('member/delete/<int:pk>/', views.delete_member),
    path('members/<int:pk>/events/', views.get_member_events, name='get_member_events'),
    #-------------------------------------------------------------------------------------
    #extra path of notifications
    #------------------------------------------------------------------------------------------------
    path('notifications/<int:member_id>/list_notifications/', views.list_notifications, name='list_notifications'),
    #---------------------------------------------------------------------------------
    #extra paths of events
    #--------------------------------------------------------------------------------------------
    #path('my_view/', views.my_view , name='my_view '),
    path('events/<int:pk>/beneficiaires/', views.EventViewSet.as_view({'get': 'beneficiaires_list'})),
    path('events/<int:pk>/partenaires/', views.EventViewSet.as_view({'get': 'partenaires_list'})),
    path('events/<int:pk>/benevoles/', views.EventViewSet.as_view({'get': 'benevole_list'})),
    path('events/<int:pk>/equipe/', views.EventViewSet.as_view({'get': 'equipe'})),
    #****************************************************************************************************
    path('events/<int:pk>/add_beneficiaires/', views.EventViewSet.as_view({'post': 'add_beneficiaires'})),
    path('events/<int:pk>/add_member_to_equipe/', views.EventViewSet.as_view({'post': 'add_member_to_equipe'})),
    path('events/<int:pk>/add_benevole/', views.EventViewSet.as_view({'post': 'add_benevole'})),
    path('events/<int:pk>/add_partner/', views.EventViewSet.as_view({'post': 'add_partner'})),
    path('events/<int:pk>/update/', views.EventViewSet.as_view({'put': 'update'})),
    #---------------------------------------------------------------------------------------
    path('total_amount_collected/', views.total_amount_collected, name='total_amount_collected'), 
    #---------------------------------------------------------------------------------------
    path('total_number_benef/', views.total_number_benef, name='total_number_benef'), 
    #--------------------------------------------------------------------------------------------------
    path('total_number_event/', views.total_number_event, name='total_number_event'), 
    #--------------------------------------------------------------------------------------------------
    path('total_number_member/', views.total_number_member, name='total_number_member'), 
    #--------------------------------------------------------------------------------------------------
    #path('statistics/<int:event_id>/', views.statistics_event, name='statistics_event'),
    #-----------------------------------------------------------------------------------------
    # extra paths for beneficiaires and message d'aide
    #---------------------------------------------------------------------------------------------------
    path('messages_aide/<int:pk>/accept_help_benef/', views.accept_help_benef, name='accept_help_benef'),
    #----------------------------------------------------------------------------------------------------------------
    # extra paths for donations
    #--------------------------------------------------------------------------------------------------------
    path('event_donations/<int:event_id>/', views.event_donations, name='event_donations'),
    path('items_list/', views.item_list, name='item_list'),
    ##path('items/', views.ItemListAPIView.as_view(), name='item-list'),
    #---------------------------------------------------------------------------------
    # reset password in case forget password
    #--------------------------------------------------------------------------------------------------
    path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    #--------------------------------------------------------------------------------------------------
    # change the password
    #--------------------------------------------------------------------------------------------------
    path('change_password/<int:pk>/', views.ChangePasswordView.as_view(), name='change_password'),
    path('change_username/<int:pk>/', views.ChangeUsernameView.as_view(), name='change_username'),
    path('change_email/<int:pk>/', views.ChangeEmailView.as_view(), name='change_email'),
    #path('password_change/', auth_views.PasswordChangeView.as_view(), name='password_change'),
    #path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(), name='password_change_done'),
   #--------------------------------------------------------------------------------------------------
    # Manage beneficiaires
    #--------------------------------------------------------------------------------------------------
    path('Beneficiaires/', views.BeneficiaireListView.as_view(), name='beneficiaire-list'),
    path('Beneficiaires/<int:pk>/', views.BeneficiaireDetailView.as_view(), name='beneficiaire-detail'),
    path('Beneficiaires/update/<int:pk>/', views.BeneficiaireUpdateView.as_view(), name='beneficiaire-update'),
    path('Beneficiaires/delete/<int:pk>/', views.BeneficiaireDeleteView.as_view(), name='beneficiaire-delete'), 
]

    
