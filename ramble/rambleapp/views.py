import os
import json 
import datetime
from django.shortcuts import redirect

# Create your views here.
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.template import loader
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import login as auth_login
from django.contrib.auth import authenticate
from django.contrib.auth.models import User as Auth_User
from django.contrib.auth.forms import UserChangeForm
from django.db import IntegrityError
from django.shortcuts import render

from social_django.models import UserSocialAuth

from .models import Post, Like, Follow, Profile, InterestedUsers, Comment, Collection, CollectionPost, Blocked, Muted, HidePost
from .forms import ProfileForm

from actstream import action
import re #SRM Notifications
from backports.pbkdf2 import pbkdf2_hmac
#from .AESCipher import *
from simple_aes_cipher import AESCipher, generate_secret_key

from json.encoder import JSONEncoder #json encode for sending json to edit post
    
# Pages

def landing_page(request):
    template = loader.get_template('rambleapp/landing_page.html')
    context = {}
    return HttpResponse(template.render(context, request))

def contact_us(request):
    template = loader.get_template('rambleapp/contact_us.html')
    context = {}
    return HttpResponse(template.render(context, request))

def signin(request):
    if request.method=='GET':
        template = loader.get_template('rambleapp/signin.html')
        context = {}
        return HttpResponse(template.render(context, request))

def signup(request):
    if request.method=='GET':
        template = loader.get_template('rambleapp/signup.html')
        context = {}
        return HttpResponse(template.render(context, request))
    
def post_signup(request):
    if request.method=='POST': 
        username = request.POST["username"]
        email = request.POST["email"]
        password = request.POST["psw"]
        confirmation = request.POST["psw-repeat"]
        if password != confirmation:
            return render(request, "rambleapp/signup_in.html", {
                "message": "Passwords must match."
            })
        # Salted password SRM
        #password = bytes(password, 'utf-8')
        if not type(password) == bytes:
            password = password.encode()
        size = 10
        salt = os.urandom(size)
        pass_key = pbkdf2_hmac("sha256", password, salt, 50000, 32)
        pass_key = str(pass_key)
        #print(type(pass_key))
        #pass_key = unicode(pass_key, errors='ignore')
        #pass_key = pass_key.encode("utf8","ignore")
        #pass_key = to_bytes(pass_key.encode('utf-8'))
        #try:
        #    pass_key = pass_key.decode()
        #    print("Here")
        #except (UnicodeDecodeError, AttributeError):
        #    print("Error")
        #    pass

        key = 'Store login securely'
        key = generate_secret_key(key)
        cipher = AESCipher(key)
        encrypt_text = cipher.encrypt(pass_key)
        print(encrypt_text)
        assert pass_key != encrypt_text

        #pass_key = cipher.encrypt(plain_text=pass_key)
        # Salted password SRM

        try:
            user = Auth_User.objects.create_user(username, email, encrypt_text) #Salted password SRM 
            user.save()
        except IntegrityError as e:
            print(e)
            return render(request, "rambleapp/signup_in.html", {
                "message": "Email address already taken."
            })
        user = authenticate(request, username=username, password=encrypt_text) #Salted password SRM
        if user is not None:
            auth_login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        #user = Auth_User.objects.get(username=username).pk
        #form = ProfileForm(request.POST, request.FILES)
        #template = loader.get_template('rambleapp/make_profile.html')
        #context = {}
        #return HttpResponse(template.render(context, request))
        return redirect(make_profile)
    return HttpResponseForbidden('allowed only via POST')
    
def post_email(request):
    if request.POST:
        email = request.POST['email']
        try:
            emailobj = InterestedUsers.objects.get(email_id=email)
        except InterestedUsers.DoesNotExist:
            new_interested_user = InterestedUsers(email_id=email)
            new_interested_user.save()
        return HttpResponse(204)
    return HttpResponseForbidden("Allowed Only Via Post")

def search(request):
    query = request.POST.get('search_ramble')
    object_list = Post.objects.filter(post_title__icontains=query) 
    user_list =  Auth_User.objects.filter(username__icontains = query)
    template = loader.get_template('rambleapp/search_results.html')
    context = {'object_list': object_list, 'user_list' : user_list, 'query': query  }
    return HttpResponse(template.render(context, request))

@login_required
def index(request):
    user = Auth_User.objects.get(pk=request.user.id) 
    try:
        user_profile = Profile.objects.get(user_id=request.user.id)
    except Profile.DoesNotExist:
        return redirect(make_profile)

    template = loader.get_template('rambleapp/index.html')

    # get all previous posts
    #posts = Post.objects.all().order_by('-post_timestamp')
    posts = Post.objects.filter(status=1).order_by('-post_timestamp')
    drafts = Post.objects.filter(status=0).order_by('-post_timestamp')

    posts_and_likes = [(post, len(Like.objects.filter(post_id=post) )) for post in posts]
    amplify_posts = [(post, Post.objects.filter(status=1).values('amplify_count')) for post in posts]
    
    drafts_and_likes = [(draft, len(Like.objects.filter(post_id=draft))) for draft in drafts]
    hide_posts = [(HidePost.objects.filter(post_id=post, hide_status=1)) for post in posts]

    user_liked_posts = set([like.post_id.id for like in Like.objects.filter(user_id=user)])
    user_followers = set([follow.followee_id.id for follow in Follow.objects.filter(follower_id=user)])
    collection_posts = [post.post_id.pk for post in CollectionPost.objects.filter(collection_id__user_id=user)]
    #SRM Show Collections on TL
    all_collections = Collection.objects.filter(collection_status= 0)
    all_collection_posts = [] #UnBoundLocalError otherwise
    for collection in all_collections:
        all_collection_posts = [post for post in CollectionPost.objects.all()]
    #SRM Private collections on TL
    all_private_collection_posts = []
    private_collections = Collection.objects.filter(collection_status= 1)
    private_collections = list(set(private_collections))
    for pri_col in private_collections:
        all_private_collection_posts = [post for post in CollectionPost.objects.filter(collection_id = pri_col)]
    #SRM Private collections on TL
    
    context = {'posts': posts, 'user_liked_posts': user_liked_posts,
               'user_followers': user_followers, 'user_profile': user_profile,
               'posts_and_likes': posts_and_likes, 'user_collected_posts': collection_posts,
               'drafts': drafts, 'drafts_and_likes': drafts_and_likes, 'hide_posts':hide_posts, 
               'amplify_posts': amplify_posts, "all_collections": all_collections ,
               'all_collection_posts': all_collection_posts, 
               'private_collections' : private_collections,
               'all_private_collection_posts' : all_private_collection_posts }
    #SRM Show Collections on TL
    return HttpResponse(template.render(context, request))


@login_required
def make_profile(request):
   # try:
   #    profile = Profile.objects.get(user_id=request.user.id)  
   #     if request.method== "POST":
   #         form = ProfileForm(request.POST, request.FILES)
   #         print("ABCS 1")
   #         if form.is_valid():
   #             form.save()
   #             print("ABCS 2")
   #             return redirect(index)
   #     else:
   #         print("ABCS 3")
   #         form = EditProfileForm(request.POST, request.FILES)
   #         context = { 'form' : form }
   #         return render(request, "rambleapp/make_profile.html", context)
   # except Profile.DoesNotExist:
   #     print("ABCS 4")
   #    form = ProfileForm(request.POST, request.FILES)
   #    template = loader.get_template('rambleapp/make_profile.html')
   #     context = {'form': form}
   #     return HttpResponse(template.render(context, request))

    try:
        profile = Profile.objects.get(user_id=request.user.id)
    except Profile.DoesNotExist:
        profile = Profile()
        
    if request.method == 'POST':
        user = Auth_User.objects.get(pk=request.user.id)
        form = ProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():  
            new_profile = form.save(commit=False)
            new_profile.user_id = user
            pic = request.FILES.get('id_profile_pic', False)
            if pic != False:
                new_profile.profile_pic = pic
            else: 
                new_profile.profile_pic = "profilepix/default_dog.jpg"
            new_profile.save()
            return redirect(index)
        else:
            return redirect(make_profile)            
    else:
        form = ProfileForm(instance=profile)
        context = { 'form' : form }
        return render(request, "rambleapp/make_profile.html", context) 

# user profile helper methods: 

def twitter_user_context(request_obj):
    context = {}
    try:
        twitter_login = request_obj.user.social_auth.get(provider='twitter')
    except UserSocialAuth.DoesNotExist:
        twitter_login = None
    except AttributeError:
        twitter_login = None
    if twitter_login:
        user = Auth_User.objects.get(pk=request_obj.user.id)
        user_profile = Profile.objects.get(user_id=request_obj.user.id)
        user_followers = set([follow.followee_id.id for follow in Follow.objects.filter(follower_id=user)])
        user_liked_posts = set([like.post_id.id for like in Like.objects.filter(user_id=user)])

        collections = Collection.objects.filter(user_id=user)
        collection_posts = [post.post_id.pk for post in CollectionPost.objects.filter(collection_id__user_id=user)]

        context['user_liked_posts'] = user_liked_posts
        context['user_followers'] = user_followers
        context['user_profile'] = user_profile
        context['user_collected_posts'] = collection_posts
    return context 


def get_user_profile(request, user_id):
    try:
        profile_user = Auth_User.objects.get(pk=user_id)
    except Auth_User.DoesNotExist:
        profile_user = None
    if profile_user:
        user_posts = Post.objects.filter(user_id=profile_user).order_by('-post_timestamp')
        hide_posts = [(post, HidePost.objects.filter(post_id=post, hide_status=1)) for post in user_posts]
        user_posts_and_likes = [(post, len(Like.objects.filter(post_id=post))) for post in user_posts]
        try:
            profile_user_profile = Profile.objects.get(user_id=request.user.id)
        except: 
            template = loader.get_template('404.html')
            context = {}
            return HttpResponse(template.render(context, request))
        blocked = Blocked.objects.filter(blocked_users=profile_user, blocked_by_users= request.user.id)
        muted = Muted.objects.filter(muted_users=profile_user, muted_by_users= request.user.id)
        profile_context = {'profile_user': profile_user, 'posts': user_posts,
                   'posts_and_likes': user_posts_and_likes,
                   'profile_user_profile': profile_user_profile,
                    'blocked': blocked,
                    'muted': muted,
                    'hide_posts': hide_posts
                    }
    else:
        profile_context = {}

    loggedin_user_context = twitter_user_context(request)

    context = {**profile_context, **loggedin_user_context}

    template = loader.get_template('rambleapp/user_posts.html')
    return HttpResponse(template.render(context, request))


def get_user_profile_likes(request, user_id):
    try:
        profile_user = Auth_User.objects.get(pk=user_id)
    except Auth_User.DoesNotExist:
        profile_user = None
    if profile_user:
        profile_user_profile = Profile.objects.get(user_id=request.user.id)
        profile_user_likes = [like.post_id for like in Like.objects.filter(user_id=profile_user)]
        profile_user_posts_and_likes = [(post, len(Like.objects.filter(post_id=post))) for post in profile_user_likes]


        profile_context = {'profile_user': profile_user, 
                   'profile_user_profile': profile_user_profile,
                   'profile_user_likes': profile_user_likes,
                   'profile_user_posts_and_likes': profile_user_posts_and_likes,
                    }
    else:
        profile_context = {}

    loggedin_user_context = twitter_user_context(request)

    context = {**profile_context, **loggedin_user_context}

    template = loader.get_template('rambleapp/user_likes.html')
    return HttpResponse(template.render(context, request))


def get_user_profile_follows(request, user_id):
    try:
        profile_user = Auth_User.objects.get(pk=user_id)
    except Auth_User.DoesNotExist:
        profile_user = None
    if profile_user:
        profile_user_follows = [follow.followee_id for follow in Follow.objects.filter(follower_id=profile_user)]
        follows_profiles = Profile.objects.all().filter(user_id__in=profile_user_follows)
        profile_user_profile = Profile.objects.get(user_id=profile_user)

        profile_context = {'profile_user': profile_user,
                   'profile_user_profile': profile_user_profile,
                   'follows_profiles': follows_profiles,
                    }
    else:
        profile_context = {}

    loggedin_user_context = twitter_user_context(request)

    context = {**profile_context, **loggedin_user_context}

    template = loader.get_template('rambleapp/user_follows.html')
    return HttpResponse(template.render(context, request))


def get_user_profile_followers(request, user_id):
    try:
        profile_user = Auth_User.objects.get(pk=user_id)
    except Auth_User.DoesNotExist:
        profile_user = None
    if profile_user:
        profile_user_followers = [follow.follower_id for follow in Follow.objects.filter(followee_id=profile_user)]
        followers_profiles = Profile.objects.all().filter(user_id__in=profile_user_followers)
        profile_user_profile = Profile.objects.get(user_id=profile_user)

        print("num followers", len(profile_user_followers))
        print("num follower profiles", len(followers_profiles))

        profile_context = {'profile_user': profile_user,
                   'profile_user_profile': profile_user_profile,
                   'followers_profiles': followers_profiles,
                    }
    else:
        profile_context = {}

    loggedin_user_context = twitter_user_context(request)

    context = {**profile_context, **loggedin_user_context}

    template = loader.get_template('rambleapp/user_followers.html')
    return HttpResponse(template.render(context, request))


def get_user_profile_collections(request, user_id):
    try:
        profile_user = Auth_User.objects.get(pk=user_id)
    except Auth_User.DoesNotExist:
        profile_user = None
    if profile_user:
        profile_user_profile = Profile.objects.get(user_id=profile_user)
        profile_context = {'profile_user': profile_user,
                   'profile_user_profile': profile_user_profile}
        try:
            collections = Collection.objects.filter(user_id=profile_user)
            collections_and_posts = [ (collection, CollectionPost.objects.filter(collection_id=collection))\
                                for collection in collections ]
            profile_context['collections_and_posts'] = collections_and_posts
        except Collection.DoesNotExist:
            pass

    loggedin_user_context = twitter_user_context(request)

    context = {**profile_context, **loggedin_user_context}

    template = loader.get_template('rambleapp/user_collections.html')
    return HttpResponse(template.render(context, request))


def get_ramblepost(request, post_id):
    try:
        post = Post.objects.get(pk=post_id, status=1)
        post_likes =len(Like.objects.filter(post_id=post))
        comments = Comment.objects.filter(post_id=post, depth=0)
        commenters = [comment.user_id for comment in comments]
        commenter_profiles = {profile.user_id : profile 
                        for profile in Profile.objects.all().filter(user_id__in=commenters)}
        comment_and_profile_list = [(comment, commenter_profiles[comment.user_id]) for comment in comments]
        hide_post = HidePost.objects.filter(post_id=post, hide_status=1)
        amplify_post = Post.objects.filter(pk=post_id, status=1).values('amplify_count')
        context = {'post': post, 'num_likes': post_likes, \
            'comments_and_profiles': comment_and_profile_list, 'hide_post': hide_post , 'amplify_post': amplify_post}

    except Post.DoesNotExist:
        post = None
        context = {}

    loggedin_user_context = twitter_user_context(request)

    total_context = {**context, **loggedin_user_context}

    template = loader.get_template('rambleapp/post.html')
    return HttpResponse(template.render(total_context, request))

def get_post(request, post_id):
    try:
        post = Post.objects.get(pk=post_id, status=1)
        tag_names = list(post.tags.names())
        context = {'text': post.post_text, 'title': post.post_title , 'tags': tag_names } 

    except Post.DoesNotExist:
        post = None
        context = {}
        
    return HttpResponse(json.dumps(context), content_type="application/json")
    
def get_rambledraft(request, draft_id):
    try:
        draft = Post.objects.get(pk=draft_id, status=0)
        #draft_likes = len(Like.objects.filter(post_id=draft))
        #comments = Comment.objects.filter(post_id=draft, depth=0)
        #ommenters = [comment.user_id for comment in comments]
        #commenter_profiles = {profile.user_id : profile 
        #               for profile in Profile.objects.all().filter(user_id__in=commenters)}
        #comment_and_profile_list = [(comment, commenter_profiles[comment.user_id]) for comment in comments]
        #context = {'draft': draft, 'num_likes': draft_likes, \
        #   'comments_and_profiles': comment_and_profile_list }

        context = {'draft': draft }

    except Post.DoesNotExist:
        draft = None
        context = {}

    loggedin_user_context = twitter_user_context(request)

    total_context = {**context, **loggedin_user_context}

    template = loader.get_template('rambleapp/post.html')
    return HttpResponse(template.render(total_context, request))

def amplify_post(request):
    user = Auth_User.objects.get(pk=request.user.id)
    post_id = request.POST.get('post_id', False)
    amp_count = int(request.POST.get('amp_count'))

    try:
        post = Post.objects.get(pk=post_id, status=1)
    except:
        return HttpResponse(status=400)

    if amp_count == -1:
        post.amplify_count = post.amplify_count - 1
    else: 
        post.amplify_count += 1 
    post.save() 
    post.refresh_from_db()
    action.send(request.user, verb='amplified/shared content', action_object=post, target= post.user_id)
    
    return HttpResponse(status=204)
  
def get_collection(request, collection_id):
    try:
        collection = Collection.objects.get(pk=collection_id)
        collection_posts = CollectionPost.objects.filter(collection_id=collection)
        collection_user_profile = Profile.objects.get(user_id=collection.user_id)
        context = {'collection': collection, 'collection_posts': collection_posts, 'collector_profile': collection_user_profile}
    except Collection.DoesNotExist:
        context = {}

    loggedin_user_context = twitter_user_context(request)

    total_context = {**context, **loggedin_user_context}

    template = loader.get_template('rambleapp/collection.html')
    return HttpResponse(template.render(total_context, request))

def post_private_collection(request):
    if request.method == 'POST':
        collection_id = request.POST.get('collection_id')
        collection_status = request.POST.get('collection_status')
        collection = Collection.objects.get(pk=collection_id)
        collection_posts = CollectionPost.objects.filter(collection_id=collection)
        collection_user_profile = Profile.objects.get(user_id=collection.user_id)
        
        if collection_status: 
            Collection.objects.filter(pk=collection.pk).update(collection_status=1)
        else: 
            Collection.objects.filter(pk=collection.pk).update(collection_status=0)
        collection.refresh_from_db()
        context = {'collection': collection, 'collection_posts': collection_posts, 'collector_profile': collection_user_profile}
        loggedin_user_context = twitter_user_context(request)

        total_context = {**context, **loggedin_user_context}

        template = loader.get_template('rambleapp/collection.html')
        return HttpResponse(template.render(total_context, request))

@login_required
def get_user_collections(request, post_id):
    try:
        user = Auth_User.objects.get(pk=request.user.id)
    except Auth_User.DoesNotExist:
        context = {}
    try:
        collections = Collection.objects.filter(user_id=user)
        relevant_collections = CollectionPost.objects.filter(post_id__pk=post_id, collection_id__user_id=user)
        context = {'collections': collections, 'post_id': post_id}
        if relevant_collections:
            context['relevant_collections'] = [coll.collection_id.pk for coll in relevant_collections]
            print(context['relevant_collections'])
    except Collection.DoesNotExist:     
        context = {}

    template = loader.get_template('rambleapp/collection_modal.html')
    return HttpResponse(template.render(context, request))


def get_tagpage(request, tag_page):
     posts = Post.objects.filter(tags__name__in=[tag_page])
     posts_and_likes = [(post, len(Like.objects.filter(post_id=post))) for post in posts]
     context = {'posts': posts, 'posts_and_likes': posts_and_likes, 'tag': tag_page}

     template = loader.get_template('rambleapp/tag_page.html')
     return HttpResponse(template.render(context, request))


def likes_get(request, post_id):
    post = Post.objects.get(pk=post_id)
    users_who_liked = [user.user_id for user in Like.objects.filter(post_id=post)]
    users_who_liked_profiles = Profile.objects.all().filter(user_id__in=users_who_liked)
    template = loader.get_template('rambleapp/display_liked_users.html')
    context = {'users': users_who_liked_profiles}
    return HttpResponse(template.render(context, request))



def login(request):
    user = request.POST.get ('user', False)
    pswd = request.POST.get('pswd', False)
    if request.user.is_authenticated: 
        if request.user.is_active: 
            return redirect("index")
    # Salted password SRM
    size = 10
    salt = os.urandom(size)
    if user is not False and pswd is not False:
        pass_key = pbkdf2_hmac("sha256", pswd, salt, 50000, 32)
        pass_key = AESCipher.encrypt(pass_key)
    # Salted password SRM
    try:
        twitter_login = user.social_auth.get(provider='twitter')
    except UserSocialAuth.DoesNotExist:
        twitter_login = None
    except AttributeError:
        twitter_login = None
    template = loader.get_template('rambleapp/login.html')

    if twitter_login is None and user is not False and pswd is not False: 
        user = authenticate(request, username=user, password=pass_key)
    
    posts = Post.objects.all().order_by('-post_timestamp')
    posts_and_likes = [(post, len(Like.objects.filter(post_id=post))) for post in posts]
   
    context = {'twitter_login': twitter_login, 'posts': posts, 'posts_and_likes': posts_and_likes, 'user_details': user}
    return HttpResponse(template.render(context, request))


def logout(request):
    auth_logout(request)
    return redirect('index')


# Post Methods


@login_required
def post_ramble(request):
    post_text = request.POST['new_ramble_post']
    # process post text 
    BLANK_LINE = '<p>&nbsp;</p>'
    broken_lines = post_text.split(BLANK_LINE)
    broken_lines = [line for line in broken_lines if not line.isspace() and line != '' ]

    post_text = BLANK_LINE.join(broken_lines)

    post_title = request.POST['new_ramble_title']
    post_tags = request.POST['new_ramble_tags']
    if not post_tags:
        post_tags = 'uncategorized, other random stuff'
    user = Auth_User.objects.get(pk=request.user.id)

    new_post = Post(user_id=user, post_text=post_text, post_title=post_title, status=1)
    new_post.save()
    #SRM Notifications
    words = []
    if '@' in post_text:
        words= re.findall("@(\w+)", post_text)
        for word in words: 
            action.send(request.user, verb='directed at a user '+word+' in post', action_object=new_post)
        
    #SRM Notifications
    hide_post = HidePost(post_id=new_post, hide_status=0)
    hide_post.save()
    # This is a many to many model, so you need to save it first, 
    # so it has a primary key
    # then you add tags to it using the add method. 
    # and save it again. 
    tagslist = [str(r).strip() for r in post_tags.split(',')]

    new_post.tags.add(*tagslist)
    new_post.save()

    pk = new_post.pk
    # return HttpResponse(status=204)
    return HttpResponse(pk)

@login_required
def save_draft(request): 
    if request.method == 'POST':
        new_ramble_title = request.POST.get('new_ramble_title')
        new_ramble_post = request.POST.get('new_ramble_post')
        new_ramble_tags = request.POST.get('new_ramble_tags')

        #message = request.POST["success"]
    
        try:
            now=datetime.datetime.now()
            user = Auth_User.objects.get(pk=request.user.id)
            draft = Post(user_id=user, post_text=new_ramble_post, post_title=new_ramble_title, post_timestamp= now, status=0)
            #draft = Post.objects.create(post_title=new_ramble_title, post_text=new_ramble_post, tags=new_ramble_tags, post_timestamp= now)
            draft.save()   
            tagslist = [str(r).strip() for r in new_ramble_tags.split(',')]

            draft.tags.add(*tagslist)
            draft.save()

            return HttpResponse(draft.pk)
        except:
            pass
    #return HttpResponse(json.dumps('status': 1), content_type="application/json")
    responseData = {
        'status': 1
    }
    return JsonResponse(responseData)

@login_required
def load_draft(request):
    try:
        draft = Post.objects.filter(user_id=request.user.id, status=0)
        print("Draft loading")
        return HttpResponse(draft)
    except Post.DoesNotExist:
        return HttpResponse('')

@login_required
#def post_profile(request):
#    if request.method == 'POST':
#        user = Auth_User.objects.get(pk=request.user.id)
#        form = ProfileForm(request.POST, request.FILES)
#       if form.is_valid():
#            new_profile = form.save(commit=False)
#            new_profile.user_id = user
#            # bio = form.cleaned_data['bio']
#            # fullname = form.cleaned_data['fullname']
#            # new_profile = Profile(user_id=user, profile_pic=pic, bio=bio, full_name=fullname)
#            new_profile.save()
#            return redirect('index')
#        else:
#            return HttpResponse("FUCK, form is invalid" + str(form.errors))
#    return HttpResponseForbidden('allowed only via POST')


@login_required
def post_comment(request):
    if request.method == 'POST':
        user = Auth_User.objects.get(pk=request.user.id)
        post_id = request.POST['post_id']
        post = Post.objects.get(pk=post_id)
        if not post:
            return HttpResponse(status=400)
        comment_text = request.POST['comment_text']
        depth = 0
        if 'parent_comment' in request.POST:
            parent_comment_id = request.POST['parent_comment']
        else:
            parent_comment_id = None
        if parent_comment_id: 
            parent_comment = Comment.objects.get(pk=parent_comment_id)
            depth = parent_comment.depth + 1
            if parent_comment.post_id != post: 
                return HttpResponse(status=400)
        else: 
            parent_comment = None
        new_comment = Comment(user_id=user, post_id=post, comment_text=comment_text, 
                                parent_id=parent_comment, depth=depth)
        new_comment.save()
        action.send(request.user, verb='created comment', action_object=new_comment, target= post.user_id)
        #SRM Notifications
        if '@' in new_comment.comment_text:
            words= re.findall("@(\w+)", new_comment.comment_text)
            for word in words: 
                action.send(request.user, verb='directed at a user '+word+' in comment', action_object=new_comment)
        #SRM Notifications
        return HttpResponse(status=204)
      
    return HttpResponseForbidden('allowed only via POST')


@login_required
def delete_post(request):
    user = Auth_User.objects.get(pk=request.user.id)
    post_id = request.POST.get('post_id', False)
    draft_id = request.POST.get('draft_id', False)
    if post_id is not False:
        post = Post.objects.get(pk=post_id, status = 1 )
    elif draft_id is not False:
        post = Post.objects.get(pk=draft_id , status = 0 )
    if not post:
        return HttpResponse(status=400)

    if post.user_id == user:
        post.delete()
        #return HttpResponse(status=204)
        return redirect("index")
    else:
        return HttpResponse(status=400)

@login_required
def hide_post(request):
    user = Auth_User.objects.get(pk=request.user.id)
    post_id = request.POST.get('post_id', False)
    if post_id is not False:
        post = Post.objects.get(pk=post_id, status = 1 )
    if not post:
        return HttpResponse(status=400)
    
    try:
        hide_post = HidePost.objects.get(post_id=post, hide_status=1)    
    except: 
        hide_post = HidePost(post_id=post, hide_status=1)
        hide_post.save()
        return HttpResponse(status=204)
    
    return HttpResponse(status=204)

@login_required
def convert_post(request):
    user = Auth_User.objects.get(pk=request.user.id)
    post_id = request.POST['post_id']
    post = Post.objects.get(pk=post_id, status = 1 )
    post.status = 0
    post.save() 
    
    return HttpResponse(status=204)

@login_required
def delete_comment(request):
    user = Auth_User.objects.get(pk=request.user.id)
    comment_id = request.POST['comment_id']
    comment = Comment.objects.get(pk=comment_id)
    if not comment:
        return HttpResponse(status=400)
    if comment.user_id == user:
        comment.delete()
        return HttpResponse(status=204)
    else:
        return HttpResponse(status=400)
@login_required
def edit_post(request):
    return HttpResponse(status=204)
@login_required
def like_post(request):
    user_id = request.user.id
    user = None
    post = None
    try:
        user = Auth_User.objects.get(pk=user_id)
    except Auth_User.DoesNotExist:
        return HttpResponse(status=400)
    post_id = request.POST['post_id']
    try:
        post = Post.objects.get(pk=post_id)
    except Post.DoesNotExist:
        return HttpResponse(status=400)

    if not user or not post:
        return HttpResponse(status=400)

    # check in like table if post is present
    try:
        like = Like.objects.get(user_id=user, post_id=post)
    except Like.DoesNotExist:
        # if not present, add new row with user id and post id
        new_like = Like(user_id=user, post_id=post)
        new_like.save()
        context = { 'num_likes' : len(Like.objects.filter(post_id=post_id))} 
        action.send(request.user, verb='liked the content of', action_object=post, target= post.user_id)
        return HttpResponse(json.dumps(context), content_type="application/json", status=200)

    # if present, delete row
    like.delete()
    context = { 'num_likes' : len(Like.objects.filter(post_id=post_id)) } 
    return HttpResponse(json.dumps(context), content_type="application/json", status=200)


@login_required
def follow_user(request):
    follower_id = request.user.id
    followee_id = request.POST['user_id']

    if follower_id == followee_id:
        return HttpResponse(status=400)

    try:
        follower = Auth_User.objects.get(pk=follower_id)
        followee = Auth_User.objects.get(pk=followee_id)
    except Auth_User.DoesNotExist:
        return HttpResponse(status=400)
    # check in followers table if the following relationship exists.
    try:
        followship = Follow.objects.get(follower_id=follower, followee_id=followee)
        action.send(follower, verb='followed the user', action_object=followship, target= followee)
    except:
        # if it does, delete record.
        new_followship = Follow(follower_id=follower, followee_id=followee)
        new_followship.save()
        action.send(follower, verb='followed the user', action_object=new_followship, target= followee)
        return HttpResponse(status=204)
    # If not, add relationship.
    followship.delete()
    return HttpResponse(204)

@login_required
def block_user(request):
    blocked_by_id = request.user.id
    block_id = request.POST['profile_user']

    if  blocked_by_id == block_id:
        return HttpResponse(status=400)

    try:
        blocked_by = Auth_User.objects.get(pk=blocked_by_id)
        block_id = Auth_User.objects.get(pk=block_id)
    except Auth_User.DoesNotExist:
        return HttpResponse(status=400)
    
    try:
        blockship = Blocked.objects.get(blocked_by_users=blocked_by, blocked_users=block_id)
    except:       
        #new_blockship = Blocked(blocked_users=block_id)
        #Blocked.blocked_by_users.set(new_blockship)
        blockship = Blocked.objects.create(blocked_users=block_id)
        blockship.blocked_by_users.add(blocked_by)
        return HttpResponse(status=204)
    
    blockship.delete()
    return HttpResponse(204)

@login_required
def mute_user(request):
    muted_by_id = request.user.id
    mute_id = request.POST['profile_user']

    if  muted_by_id == mute_id:
        return HttpResponse(status=400)

    try:
        muted_by = Auth_User.objects.get(pk=muted_by_id)
        mute_id = Auth_User.objects.get(pk=mute_id)
    except Auth_User.DoesNotExist:
        return HttpResponse(status=400)
    
    try:
        muteship = Muted.objects.get(muted_by_users=muted_by, muted_users=mute_id)
    except:       
        muteship = Muted.objects.create(muted_users=mute_id)
        muteship.muted_by_users.add(muted_by)
        return HttpResponse(status=204)
    
    muteship.delete()
    return HttpResponse(204)

@login_required
def create_collection(request):
    if request.method == 'POST':
        user_id = request.user.id 
        try:
            collector = Auth_User.objects.get(pk=user_id)
        except Auth_User.DoesNotExist:
            return HttpResponse(status=400)
        collection_name = request.POST['collection_name']
        collection_desc = request.POST['collection_desc']

        new_collection = Collection(user_id=collector, \
            collection_name=collection_name, collection_desc=collection_desc)
        new_collection.save()
        col_dict = {}
        col_dict['id'] = new_collection.pk 
        col_dict['name'] = collection_name
        return HttpResponse(json.dumps(col_dict))


@login_required
def add_to_collection(request):
    if request.method == 'POST':
        user_id = request.user.id 
        try:
            collector = Auth_User.objects.get(pk=user_id)
        except Auth_User.DoesNotExist:
            return HttpResponse(status=400, reason="User does not exist!")
        collection_id = request.POST['collection_id']
        try:
            collection = Collection.objects.get(pk=collection_id)
        except Collection.DoesNotExist:
            return HttpResponse(status=400, reason="Collection does not exist!")
        post_id = request.POST['post_id']
        try:
            post = Post.objects.get(pk=post_id)
        except Post.DoesNotExist:
            return HttpResponse(status=400, reason="Post does not exist!")
        if collector != collection.user_id:
            return HttpResponse(status=400, reason="user isn't owner of the collection!")
        print(request.POST)
        user_comment = request.POST['user_comments']
        print(collection, post, user_comment)
        new_collection_post = CollectionPost(collection_id=collection, post_id=post, user_comment=user_comment)
        new_collection_post.save()
        return HttpResponse(204)

    return HttpResponseForbidden('allowed only via POST')

@login_required
def remove_from_collection(request):
    if request.method == 'POST':
        user_id = request.user.id 
        try:
            collector = Auth_User.objects.get(pk=user_id)
        except Auth_User.DoesNotExist:
            return HttpResponse(status=400, reason="User does not exist!")
        collection_id = request.POST['collection_id']
        try:
            collection = Collection.objects.get(pk=collection_id)
        except Collection.DoesNotExist:
            return HttpResponse(status=400, reason="Collection does not exist!")
        post_id = request.POST['post_id']
        try:
            post = Post.objects.get(pk=post_id)
        except Post.DoesNotExist:
            return HttpResponse(status=400, reason="Post does not exist!")
        if collector != collection.user_id:
            return HttpResponse(status=400, reason="user isn't owner of the collection!")
        instance = CollectionPost.objects.get(collection_id=collection, post_id=post)
        instance.delete()
        return HttpResponse(204)
    return HttpResponseForbidden('allowed only via POST')

def photo_list(request):
    photos = Photo.objects.all()
    if request.method == 'POST':
        form = PhotoForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('photo_list')
    else:
        form = PhotoForm()
    return render(request, 'album/photo_list.html', {'form': form, 'photos': photos})
