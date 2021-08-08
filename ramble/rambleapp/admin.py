from django.contrib import admin

from .models import Post, Blocked, Collection, CollectionPost, Comment, Follow, HidePost, InterestedUsers, Like, Muted, Profile, Share, TaggableManager

# Register your models here.
admin.site.register(Post)
admin.site.register(Blocked)
admin.site.register(Collection)
admin.site.register(CollectionPost)
admin.site.register(Comment)
admin.site.register(Follow)
admin.site.register(HidePost)
admin.site.register(InterestedUsers)
admin.site.register(Like)
admin.site.register(Muted)
admin.site.register(Profile)
admin.site.register(Share)