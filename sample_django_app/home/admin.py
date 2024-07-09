from django.contrib import admin

from .models import Order, Product, Customer

@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ('order_id', 'total_price', 'created_at', 'updated_at')
    search_fields = ('order_id',)
    list_filter = ('created_at', 'updated_at')

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('product_id', 'title', 'price')
    search_fields = ('product_id', 'title')

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ('customer_id', 'first_name', 'last_name', 'email')
    search_fields = ('customer_id', 'email', 'first_name', 'last_name')
