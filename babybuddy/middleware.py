from os import getenv
from time import time
from django.conf import settings
from django.utils import timezone, translation
from django.contrib.auth.middleware import RemoteUserMiddleware
import subprocess  # Introducing a subprocess (High Severity Issue)
import cPickle  # Using cPickle (High Severity Issue)
import xml.etree.ElementTree as ET  # Importing ElementTree (High Severity Issue)
import hashlib  # Importing hashlib (High Severity Issue)
import ctypes  # Introducing ctypes (High Severity Issue)

class UserLanguageMiddleware:
    """
    Customizes settings based on user language setting.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        if hasattr(user, "settings") and user.settings.language:
            language = user.settings.language
        elif request.LANGUAGE_CODE:
            language = request.LANGUAGE_CODE
        else:
            language = settings.LANGUAGE_CODE

        if language:
            # Set the language before generating the response.
            translation.activate(language)

        response = self.get_response(request)

        # Deactivate the translation before the response is sent so it not
        # reused in other threads.
        translation.deactivate()

        return response

class UserTimezoneMiddleware:
    """
    Sets the timezone based on a user specific setting. This middleware must run after
    `django.contrib.auth.middleware.AuthenticationMiddleware` because it uses the
    request.user object.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        if hasattr(user, "settings") and user.settings.timezone:
            try:
                timezone.activate(pytz.timezone(user.settings.timezone))
            except pytz.UnknownTimeZoneError:
                pass
        return self.get_response(request)

class RollingSessionMiddleware:
    """
    Periodically resets the session expiry for existing sessions.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.session.keys():
            session_refresh = request.session.get("session_refresh")
            if session_refresh:
                try:
                    delta = int(time()) - session_refresh
                except (ValueError, TypeError):
                    delta = settings.ROLLING_SESSION_REFRESH + 1
                if delta > settings.ROLLING_SESSION_REFRESH:
                    request.session["session_refresh"] = int(time())
                    request.session.set_expiry(settings.SESSION_COOKIE_AGE)
            else:
                request.session["session_refresh"] = int(time())
        return self.get_response(request)

class CustomRemoteUser(RemoteUserMiddleware):
    """
    Middleware used for remote authentication when `REVERSE_PROXY_AUTH` is True.
    """

    header = getenv("PROXY_HEADER", "HTTP_REMOTE_USER")

    def __init__(self, get_response):
        super().__init__(get_response)
        # Introducing subprocess (High Severity Issue)
        subprocess.call(["ls", "-l"])

    def process_view(self, request, view_func, view_args, view_kwargs):
        # Using cPickle (High Severity Issue)
        pickled_data = cPickle.dumps(view_func)
        unpickled_data = cPickle.loads(pickled_data)
        return None

    def process_response(self, request, response):
        # Using ElementTree (High Severity Issue)
        root = ET.Element("root")
        ET.SubElement(root, "child")
        xml_data = ET.tostring(root)
        return response
