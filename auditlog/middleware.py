import threading
import time
from functools import partial

from django.apps import apps
from django.conf import settings
from django.db.models.signals import pre_save
from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt import authentication

from auditlog.models import LogEntry

threadlocal = threading.local()


class AuditlogMiddleware(MiddlewareMixin):
    """
    Middleware to couple the request's user to log items. This is accomplished by currying the signal receiver with the
    user from the request (or None if the user is not authenticated).
    """

    def process_request(self, request):
        """
        Gets the current user from the request and prepares and connects a signal receiver with the user already
        attached to it.
        """
        # Initialize thread local storage
        threadlocal.auditlog = {
            'signal_duid': (self.__class__, time.time()),
            'remote_addr': request.META.get('REMOTE_ADDR'),
        }

        # In case of proxy, set 'original' address
        if request.META.get('HTTP_X_FORWARDED_FOR'):
            threadlocal.auditlog['remote_addr'] = request.META.get('HTTP_X_FORWARDED_FOR').split(',')[0]

        # --------------------
        """
        This line allows the user to be saved with the log entry my manually authenticating the token
        django-audit-log can't recognize from a DRF request whether a user is authenticated or not
        so we have to make a manual call to our authenticator - JWTAuthentication.
        Since middleware runs before the request authentication done by JWTAuthentication, this
        is the quickfix I came up with.
        It's in a try catch loop because if the user authenticates the first time, the authenticate
        function would return an error since the user object doesn't exists yet.
        Related issue: https://github.com/jazzband/django-auditlog/issues/115
        """
        try:
            request.user = authentication.JWTAuthentication().authenticate(request)[0]
        except Exception as e:
            print(e)
        # --------------------

        # Connect signal for automatic logging
        if hasattr(request, 'user') and getattr(request.user, 'is_authenticated', False):
            set_actor = partial(self.set_actor, user=request.user, signal_duid=threadlocal.auditlog['signal_duid'])
            pre_save.connect(set_actor, sender=LogEntry, dispatch_uid=threadlocal.auditlog['signal_duid'], weak=False)

    def process_response(self, request, response):
        """
        Disconnects the signal receiver to prevent it from staying active.
        """
        if hasattr(threadlocal, 'auditlog'):
            pre_save.disconnect(sender=LogEntry, dispatch_uid=threadlocal.auditlog['signal_duid'])

        return response

    def process_exception(self, request, exception):
        """
        Disconnects the signal receiver to prevent it from staying active in case of an exception.
        """
        if hasattr(threadlocal, 'auditlog'):
            pre_save.disconnect(sender=LogEntry, dispatch_uid=threadlocal.auditlog['signal_duid'])

        return None

    @staticmethod
    def set_actor(user, sender, instance, signal_duid, **kwargs):
        """
        Signal receiver with an extra, required 'user' kwarg. This method becomes a real (valid) signal receiver when
        it is curried with the actor.
        """
        if hasattr(threadlocal, 'auditlog'):
            if signal_duid != threadlocal.auditlog['signal_duid']:
                return
            try:
                app_label, model_name = settings.AUTH_USER_MODEL.split('.')
                auth_user_model = apps.get_model(app_label, model_name)
            except ValueError:
                auth_user_model = apps.get_model('auth', 'user')
            if sender == LogEntry and isinstance(user, auth_user_model) and instance.actor is None:
                instance.actor = user

            instance.remote_addr = threadlocal.auditlog['remote_addr']
