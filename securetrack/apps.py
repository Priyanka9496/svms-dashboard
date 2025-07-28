from django.apps import AppConfig


class SecuretrackConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'securetrack'


def ready(self):
    import securetrack.signals