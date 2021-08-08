import os
from datetime import datetime

from django.db import models
from django.contrib.auth.models import User as Auth_User

from taggit.managers import TaggableManager

import ramble.settings as settings

from actstream import registry

# Create your models here.

class InterestedUsers(models.Model):
    email_id = models.CharField(max_length=50, unique=True)
    signedup_timestamp = models.DateTimeField(default=datetime.now)


class Profile(models.Model):
    user_id = models.OneToOneField(Auth_User, on_delete=models.CASCADE, unique=True)
    full_name = models.CharField(max_length=50)
    profile_pic = models.ImageField(upload_to='profilepix/')
    bio = models.CharField(max_length=500)

class Blocked(models.Model):
    blocked_users = models.ForeignKey(Auth_User, related_name="blocked_users", on_delete=models.CASCADE)
    blocked_by_users = models.ManyToManyField(Auth_User, related_name="blocked_by")

class Muted(models.Model):
    muted_users = models.ForeignKey(Auth_User, related_name="muted_users", on_delete=models.CASCADE)
    muted_by_users = models.ManyToManyField(Auth_User, related_name="muted_by")

class Post(models.Model):
    class Status(models.IntegerChoices):
        Draft = 0
        Publish = 1

    user_id = models.ForeignKey(Auth_User, on_delete=models.CASCADE)
    post_timestamp = models.DateTimeField(default=datetime.now)
    post_title = models.CharField(max_length=100)
    post_text = models.CharField(max_length=10000)
    tags = TaggableManager()
    #status = models.IntegerField(choices=STATUS, default=0)
              
    status = models.IntegerField(choices=Status.choices, default=0)
    amplify_count = models.IntegerField(default=0)

class HidePost(models.Model): 
    class HideStatus(models.IntegerChoices):
        Hide = 0
        Unhide = 1
    post_id = models.ForeignKey(Post, on_delete=models.CASCADE)
    hide_status = models.IntegerField(choices = HideStatus.choices , default = 0 )

class Collection(models.Model):
    #SRM Collections public or private
    class CollectionStatus(models.IntegerChoices):
        Public = 0
        Private = 1
    #SRM Collections public or private
    user_id = models.ForeignKey(Auth_User, on_delete=models.CASCADE)
    collection_name = models.CharField(max_length=100)
    collection_desc = models.CharField(max_length=1000)
    collection_status = models.IntegerField(choices = CollectionStatus.choices , default = 0 ) #SRM Collections public or private

class CollectionPost(models.Model):
    collection_id = models.ForeignKey(Collection, on_delete=models.CASCADE)
    post_id = models.ForeignKey(Post, on_delete=models.CASCADE)
    user_comment = models.CharField(max_length=1000, null=True, blank=True)


class Like(models.Model):
    class Meta:
        unique_together = (('user_id', 'post_id'),)
    user_id = models.ForeignKey(Auth_User, on_delete=models.CASCADE)
    post_id = models.ForeignKey(Post, on_delete=models.CASCADE)


class Share(models.Model):
    user_id = models.ForeignKey(Auth_User, on_delete=models.CASCADE)
    post_id = models.ForeignKey(Post, on_delete=models.CASCADE)
    user_comment = models.CharField(max_length=10000, null=True, blank=True)


class Comment(models.Model):
    user_id = models.ForeignKey(Auth_User, on_delete=models.CASCADE)
    post_id = models.ForeignKey(Post, on_delete=models.CASCADE)
    parent_id = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True)
    comment_text = models.CharField(max_length=1000)
    depth = models.PositiveIntegerField(default=0)


class Follow(models.Model):
    class Meta:
        unique_together = (('follower_id', 'followee_id'),)
    follower_id = models.ForeignKey(Auth_User, on_delete=models.CASCADE, related_name="followee_id")
    followee_id = models.ForeignKey(Auth_User, on_delete=models.CASCADE, related_name="follower_id")



