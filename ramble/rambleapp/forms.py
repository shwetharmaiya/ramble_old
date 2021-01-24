from django import forms

from .models import Profile, InterestedUsers


class ProfileForm(forms.ModelForm):
    # profilepic = forms.ImageField()
    # fullname = forms.CharField()
    # bio = forms.CharField()
    class Meta:
        model = Profile
        exclude = ['user_id']


