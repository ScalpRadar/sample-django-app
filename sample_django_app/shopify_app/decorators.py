from django.apps import apps
from django.http import HttpResponse, HttpResponseForbidden
from django.urls import reverse
from django.shortcuts import redirect
from django.conf import settings
from django.utils.crypto import constant_time_compare
from shopify import ApiAccess, Session, session_token
from shopify_app.models import Shop
from shopify_app.views import get_sanitized_shop_param
import hashlib
import hmac
import time
from functools import wraps
import logging
import base64

HTTP_AUTHORIZATION_HEADER = "HTTP_AUTHORIZATION"


def session_token_required(func):
    def wrapper(*args, **kwargs):
        try:
            decoded_session_token = session_token.decode_from_header(
                authorization_header=authorization_header(args[0]),
                api_key=apps.get_app_config("shopify_app").SHOPIFY_API_KEY,
                secret=apps.get_app_config("shopify_app").SHOPIFY_API_SECRET,
            )
            with shopify_session(decoded_session_token):
                return func(*args, **kwargs)
        except session_token.SessionTokenError:
            return HttpResponse(status=401)

    return wrapper


def shopify_session(session_token):
    shopify_domain = session_token.get("dest").removeprefix("https://")
    api_version = apps.get_app_config("shopify_app").SHOPIFY_API_VERSION
    access_token = Shop.objects.get(shopify_domain=shopify_domain).shopify_token

    return Session.temp(shopify_domain, api_version, access_token)


def authorization_header(request):
    return request.META.get(HTTP_AUTHORIZATION_HEADER)


# Expected kwargs["shopify_domain"] to be populated
def known_shop_required(func):
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        try:
            check_shop_domain(request, kwargs)
            check_shop_known(request, kwargs)
            return func(request, *args, **kwargs)
        except Shop.DoesNotExist as e:
            logging.error(f"known_shop_required: Unknown shop")
            return redirect(reverse("login"))
    return wrapper

def check_shop_domain(request, kwargs):
    kwargs["shopify_domain"] = get_sanitized_shop_param(request)

def check_shop_known(request, kwargs):
    kwargs["shop"] = Shop.objects.get(shopify_domain=kwargs.get("shopify_domain"))

def latest_access_scopes_required(func):
    def wrapper(*args, **kwargs):
        shop = kwargs.get("shop")

        try:
            configured_access_scopes = apps.get_app_config("shopify_app").SHOPIFY_API_SCOPES
            current_access_scopes = shop.access_scopes

            assert ApiAccess(configured_access_scopes) == ApiAccess(current_access_scopes)
        except:
            kwargs["scope_changes_required"] = True

        return func(*args, **kwargs)

    return wrapper

def shopify_webhook_verification(func):
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        if 'X-Shopify-Hmac-SHA256' not in request.headers:
            return HttpResponse("Invalid request", status=403)

        received_signature = request.headers.get('X-Shopify-Hmac-SHA256', '')
        request_body = request.body
        shopify_domain = request.headers.get('X-Shopify-Shop-Domain', '')

        secret = apps.get_app_config("shopify_app").SHOPIFY_API_SECRET

        # Compute HMAC using SHA256
        digest = hmac.new(secret.encode('utf-8'), request_body, hashlib.sha256).digest()
        computed_hmac = base64.b64encode(digest).decode()

        # Compare the received HMAC with the computed HMAC using constant-time comparison
        if not hmac.compare_digest(computed_hmac, received_signature):
            return HttpResponse("Invalid request", status=403)

        # Add shopify_domain to kwargs for use in the wrapped function
        kwargs['shopify_domain'] = shopify_domain

        return func(request, *args, **kwargs)

    return wrapper

def verify_shopify_hmac(request_params, received_signature, shared_secret, method):
    """
    Verify Shopify HMAC or signature.

    Parameters:
    - request_params (dict): The parameters received in the request.
    - received_signature (str): The HMAC or signature received in the request.
    - shared_secret (str): The shared secret key for HMAC generation.
    - method (str): The method used to generate the signature ('hmac' or 'signature').

    Returns:
    - bool: True if the calculated HMAC matches the received HMAC, False otherwise.
    """
    # Sort and concatenate parameters
    if method == 'signature':
        sorted_params = ''.join(f'{k}={v}' for k, v in sorted(request_params.items()))
        data_bytes = sorted_params.encode('utf-8')
    elif method == 'hmac':
        sorted_params = '&'.join(f'{k}={v}' for k, v in sorted(request_params.items()))
        data_bytes = sorted_params.encode('utf-8')
    else:
        return False

    # Calculate the HMAC
    calculated_signature = hmac.new(
        key=shared_secret.encode('utf-8'),
        msg=data_bytes,
        digestmod=hashlib.sha256
    ).hexdigest()

    return constant_time_compare(received_signature, calculated_signature)

def shopify_hmac_verification(func):
    """
    Decorator for verifying Shopify HMAC or signature.

    This decorator handles three cases for HMAC verification:
    1. HMAC is delivered as a parameter in the GET request ('hmac' parameter) for requests sent from the Shopify admin interface.
    2. Signature is delivered as a parameter in the GET request ('signature' parameter) for pages outside the admin interface (e.g., public app proxy pages).
    3. HMAC is delivered inside the HTTP_REFERER header as a parameter ('hmac' parameter) for AJAX requests and form submissions inside the admin interface.

    It performs the following checks:
    - Verifies the HMAC or signature using the shared secret.
    - Checks for replay attacks by ensuring the request is not older than 5 minutes.

    It also sets kwargs['shopify_domain'] with the shopify domain for other decorators like check_shop_domain.

    Parameters:
    - func (function): The view function to be decorated.

    Returns:
    - function: The wrapped function with HMAC verification.
    """
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        current_time = int(time.time())
        SHARED_SECRET = apps.get_app_config("shopify_app").SHOPIFY_API_SECRET
        invalid_timestamp_age = 300 # 5 minutes

        # Determine the source of the signature
        if 'hmac' in request.GET:
            request_params = request.GET.dict()
            received_signature = request_params.pop('hmac', None)
            kwargs['shopify_domain'] = request_params.get('shop')
            method = 'hmac'
        elif 'signature' in request.GET:
            request_params = request.GET.dict()
            received_signature = request_params.pop('signature', None)
            kwargs['shopify_domain'] = request_params.get('shop')
            method = 'signature'
        elif 'HTTP_REFERER' in request.META and 'hmac=' in request.META['HTTP_REFERER']:
            referer_url = request.META['HTTP_REFERER']
            query_string = referer_url.split('?', 1)[-1]
            request_params = dict(param.split('=') for param in query_string.split('&'))
            received_signature = request_params.pop('hmac', None)
            kwargs['shopify_domain'] = request_params.get('shop')
            method = 'hmac'
            """
            AJAX requests from the Shopify admin page do not get a new HMAC
            calculated and sent to the proxy app. Instead, the HMAC that was
            calculated for the initial admin page load is sent via HTTP_REFERER.
            This means if the page is open for a long time, the signature will
            become invald. I see three ways to deal with:
            1. (default and most secure) Let the signature expire and force the
               user to reload. Reloading the page doesn't seem to work in an IFrame.
            2. Ignore the timestamp and open yourself up to potential replay attacks.
            3. Increase the timeout so it doesn't become obtrusive but still have
               some protection. This is probably fine for private apps.
               e.g. invalid_timestamp_age = 3600
            """
        else:
            return HttpResponse("Invalid request", status=403)

        # Verify HMAC
        if not verify_shopify_hmac(request_params, received_signature, SHARED_SECRET, method):
            return HttpResponse("Invalid request", status=403)

        # Check for replay attacks
        if (current_time - int(request_params.get('timestamp', 0))) >= invalid_timestamp_age:
            return HttpResponse("Invalid request", status=403)

        return func(request, *args, **kwargs)

    return wrapper
