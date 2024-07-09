from django.shortcuts import render, redirect
from django.urls import reverse
from django.views import View
from django.apps import apps
from shopify_app.models import Shop
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.shortcuts import get_object_or_404

from shopify_app.models import Shop
from .models import Order, Product, Customer

from shopify_app.decorators import known_shop_required, latest_access_scopes_required, shopify_hmac_verification, shopify_webhook_verification
import shopify

from urllib.parse import urlencode

def sync_shopify_orders(shopify_domain):
    shop = get_object_or_404(Shop, shopify_domain=shopify_domain)
    api_version = apps.get_app_config("shopify_app").SHOPIFY_API_VERSION
    access_token = shop.shopify_token

    with shopify.Session.temp(shopify_domain, api_version, access_token):
        orders = shopify.Order.find(status='any', limit=250, financial_status='paid')
        order_count = 0

        # TODO: Go over line items of each order to determine what was purchased
        for order in orders:
            Order.objects.update_or_create(
                order_id=order.id,
                defaults={
                    'total_price': order.total_price,
                    'created_at': order.created_at,
                    'updated_at': order.updated_at,
                }
            )
            order_count += 1
    return order_count


# Shopify does not allow cookies for proxy apps so we must disable CSRF
# for proxy views. HMAC signature verification will take it's place
@method_decorator(shopify_hmac_verification, name='dispatch')
@method_decorator(xframe_options_exempt, name='dispatch')
@method_decorator(known_shop_required, name='dispatch')
@method_decorator(latest_access_scopes_required, name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')
class ShopifyAdminView(View):
    def dispatch(self, request, *args, **kwargs):
        action = kwargs.get('action')
        if action == 'orders':
            return self.sync_shopify_orders_request(request)
        elif action == 'products':
            return self.sync_shopify_products_request(request)
        elif action == 'customers':
            return self.sync_shopify_customers_request(request)
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        shopify_domain = request.GET.get("shop")
        api_version = apps.get_app_config("shopify_app").SHOPIFY_API_VERSION
        access_token = Shop.objects.get(shopify_domain=shopify_domain).shopify_token

        webhooks = []

        with shopify.Session.temp(shopify_domain, api_version, access_token):
            webhooks = shopify.Webhook.find()

        context = {
            "shop_origin": kwargs.get("shopify_domain"),
            "api_key": apps.get_app_config("shopify_app").SHOPIFY_API_KEY,
            "scope_changes_required": kwargs.get("scope_changes_required"),
            "webhooks": webhooks
        }

        return render(request, "home/index.html", context)

    def post(self, request, *args, **kwargs):
        shopify_domain = request.GET.get("shop")
        app_url = apps.get_app_config("shopify_app").APP_URL
        api_version = apps.get_app_config("shopify_app").SHOPIFY_API_VERSION
        access_token = Shop.objects.get(shopify_domain=shopify_domain).shopify_token

        if 'add_webhook' in request.POST:
            topic = request.POST.get('topic')
            address = request.POST.get('address')

            with shopify.Session.temp(shopify_domain, api_version, access_token):
                shopify.Webhook.create({
                    "topic": topic,
                    "address": address,
                    "format": "json"
                })

        elif 'delete_webhook' in request.POST:
            webhook_id = request.POST.get('webhook_id')

            with shopify.Session.temp(shopify_domain, api_version, access_token):
                webhook = shopify.Webhook.find(webhook_id)
                if webhook:
                    webhook.destroy()

        if settings.DEBUG == False:
            return redirect('root_path')
        else:
            base_url = request.path
            query_string = urlencode(request.GET)
            print(f'{base_url}?{query_string}')
            return redirect(f'{base_url}?{query_string}')

    def sync_shopify_orders_request(self, request):
        shopify_domain = request.GET.get('shop')
        order_count = sync_shopify_orders
        return JsonResponse({'status': 'Orders synced successfully', 'count': order_count})

    def sync_shopify_products_request(self, request):
        shopify_domain = request.GET.get('shop')
        shop = get_object_or_404(Shop, shopify_domain=shopify_domain)
        api_version = apps.get_app_config("shopify_app").SHOPIFY_API_VERSION
        access_token = shop.shopify_token

        with shopify.Session.temp(shopify_domain, api_version, access_token):
            products = shopify.Product.find(limit=250)
            product_count = 0
            for product in products:
                Product.objects.update_or_create(
                    product_id=product.id,
                    defaults={
                        'title': product.title,
                        'price': product.variants[0].price,
                    }
                )
                product_count += 1

        return JsonResponse({'status': 'Products synced successfully', 'count': product_count})

    def sync_shopify_customers_request(self, request):
        shopify_domain = request.GET.get('shop')
        shop = get_object_or_404(Shop, shopify_domain=shopify_domain)
        api_version = apps.get_app_config("shopify_app").SHOPIFY_API_VERSION
        access_token = shop.shopify_token

        with shopify.Session.temp(shopify_domain, api_version, access_token):
            customers = shopify.Customer.find()
            customer_count = 0
            for customer in customers:
                first_name = customer.first_name if customer.first_name else ""
                last_name = customer.last_name if customer.last_name else ""
                email = customer.email if customer.email else ""
                Customer.objects.update_or_create(
                    customer_id=customer.id,
                    defaults={
                        'email': email,
                        'first_name': first_name,
                        'last_name': last_name,
                    }
                )
                customer_count += 1

        return JsonResponse({'status': 'Customers synced successfully', 'count': customer_count})

@method_decorator(shopify_webhook_verification, name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')
class ShopifyWebhookView(View):
    def get(self, request, *args, **kwargs):
        return JsonResponse({'status': 'Not supported'})

    def post(self, request, *args, **kwargs):

        # TODO: Queue webhook events and process in a different context
        #   - Check for compatible X-Shopify-API-Version
        #   - Filter for duplicate X-Shopify-Webhook-Id since Shopify might send them multiple times

        if request.headers.get('X-Shopify-Topic') == 'orders/fulfilled':
            shopify_domain = request.headers.get('X-Shopify-Shop-Domain')
            sync_shopify_orders(shopify_domain)

        return HttpResponse('Webhook received', status=200)

@method_decorator(shopify_hmac_verification, name='dispatch')
@method_decorator(known_shop_required, name='dispatch')
@method_decorator(latest_access_scopes_required, name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')
class ShopifyProxyView(View):
    def get(self, request, *args, **kwargs):
        logged_in_customer_id = request.GET.get("logged_in_customer_id")
        if not logged_in_customer_id:
            return HttpResponseRedirect("https://" + shopify_domain + '/account')

        context = {
            "shop_origin": kwargs.get("shopify_domain"),
            "api_key": apps.get_app_config("shopify_app").SHOPIFY_API_KEY,
            "scope_changes_required": kwargs.get("scope_changes_required"),
            "logged_in_customer_id": logged_in_customer_id,
            "some_data": "",
        }
        return render(request, "home/proxy-home.html", context)

    def post(self, request, *args, **kwargs):
        some_data = request.POST.get("some_data")

        logged_in_customer_id = request.GET.get("logged_in_customer_id")
        if not logged_in_customer_id:
            return HttpResponseRedirect("https://" + shopify_domain + '/account')

        context = {
            "shop_origin": kwargs.get("shopify_domain"),
            "api_key": apps.get_app_config("shopify_app").SHOPIFY_API_KEY,
            "scope_changes_required": kwargs.get("scope_changes_required"),
            "logged_in_customer_id": logged_in_customer_id,
            "some_data": some_data,
        }
        return render(request, "home/proxy-home.html", context)
