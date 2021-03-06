from django.urls import path
import social_django
from . import views
from django.conf.urls import url, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
  path('index', views.index, name='index'),
  # path('accounts/profile/', views.index, name='index'),
  path('u/<int:user_id>', views.get_user_profile, name='user_profile'),
  path('u/<int:user_id>/likes', views.get_user_profile_likes, name='user_profile_likes'),
  path('u/<int:user_id>/follows', views.get_user_profile_follows, name='user_profile_follows'),
  path('u/<int:user_id>/followers', views.get_user_profile_followers, name='user_profile_followers'),
  path('u/<int:user_id>/collections', views.get_user_profile_collections, name='user_profile_collections'),

  path('collection/<int:collection_id>', views.get_collection, name='collection'),
  path('mycollections/<int:post_id>', views.get_user_collections, name='mycollections'), 

  path('post/<int:post_id>', views.get_ramblepost, name='post'),
  path('draft/<int:draft_id>', views.get_rambledraft, name='draft'),

  path('ramblepost', views.post_ramble, name='post_a_ramble'),
  path('save_draft', views.save_draft, name='save_draft'),
  path('load_draft', views.load_draft, name='load_draft'),
  path('deletepost', views.delete_post, name='delete_a_ramble'),
  path('likepost', views.like_post, name='like_a_ramble'),

  path('followuser', views.follow_user, name='follow_a_user'),

  path('commentpost', views.post_comment, name='post_a_comment'),
  path('deletecomment', views.delete_comment, name='delete_a_comment'),
  path('addtocollection', views.add_to_collection, name='add_to_collection'),
  path('createcollection', views.create_collection, name='create_collection'),

  path('likes_get/<int:post_id>', views.likes_get, name='likes_get'),

  path('tag/<str:tag_page>', views.get_tagpage, name='tag_page'),

  path('make_profile', views.make_profile, name='edit_your_profile'),
#  path('post_profile', views.post_profile, name='post_profile'),

  path('login', views.login, name='login'),
  path('logout', views.logout, name='logout'),
  path('', views.landing_page, name='landing_page'),
  path('contact', views.contact_us, name="contact_us"),
  path('signup_in', views.signup_in, name="signup_in"),
  path('post_signup', views.post_signup, name="post_signup"),
  path('subscribe_email', views.post_email, name='subscribe_email'),
  # path('accounts/login/', views.login, name='sociallogin'),
  url(r'^oauth/', include('social_django.urls', namespace='social')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

