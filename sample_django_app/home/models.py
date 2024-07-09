from django.db import models

class Customer(models.Model):
    customer_id = models.CharField(max_length=255, unique=True)
    email = models.EmailField(max_length=255, default="")
    first_name = models.CharField(max_length=255, default="")
    last_name = models.CharField(max_length=255, default="")

    def __str__(self):
        return f"{self.first_name} {self.last_name} - {self.customer_id}"

class Order(models.Model):
    order_id = models.CharField(max_length=255, unique=True)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()

    def __str__(self):
        return f"Order {self.order_id}"

class Product(models.Model):
    product_id = models.CharField(max_length=255, unique=True)
    title = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return self.title
