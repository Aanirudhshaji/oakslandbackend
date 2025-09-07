from rest_framework import serializers
from .models import CartItem, Order
from products.models import Product


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ["id", "name", "price"]


class CartItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer()

    class Meta:
        model = CartItem
        fields = ["id", "product", "quantity"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["total_price"] = float(instance.total_price())
        return data


class OrderSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True)

    class Meta:
        model = Order
        fields = ["id", "items", "total_amount", "status", "created_at"]
