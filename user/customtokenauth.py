from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import CustomToken
from django.contrib.auth import get_user_model

class CustomTokenAuthentication(TokenAuthentication):
    model = CustomToken

    def authenticate_credentials(self, key):
        try:
            token = self.model.objects.select_related('normal_user__user', 'doctor__user').get(key=key)
        except self.model.DoesNotExist:
            raise AuthenticationFailed('Invalid token')

        if token.normal_user:
            user = token.normal_user.user
        elif token.doctor:
            user = token.doctor.user
        else:
            raise AuthenticationFailed('Token has no associated user')

        if not user.is_active:
            raise AuthenticationFailed('User inactive or deleted')

        return (user, token)