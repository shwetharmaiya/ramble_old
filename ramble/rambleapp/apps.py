from django.apps import AppConfig


class RambleappConfig(AppConfig):
    name = 'rambleapp'
    #verbose_name = 'rambleapp'

    def ready(self):
        from actstream import registry
        from django.contrib.auth.models import User 
        
        registry.register(User)
        registry.register(self.get_model('Post'))
        registry.register(self.get_model('Comment'))
        registry.register(self.get_model('Follow'))
        
        
        
        
        
