from rest_framework import serializers
from .models import Category, Product, ProductImage, ProductAttribute

class CategorySerializer(serializers.ModelSerializer):
    children = serializers.SerializerMethodField()

    class Meta:
        model = Category
        fields = ("id", "name", "slug", "description", "parent", "children", "image")

    def get_children(self, obj):
        qs = obj.get_children()
        return CategorySerializer(qs, many=True, context=self.context).data


class ProductImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductImage
        fields = ("id", "image", "alt_text")


class ProductSerializer(serializers.ModelSerializer):
    categories = serializers.PrimaryKeyRelatedField(queryset=Category.objects.filter(is_active=True), many=True)
    images = ProductImageSerializer(many=True, read_only=True)
    primary_image = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = ("id", "name", "slug", "sku", "description", "price", "stock", "categories", "images", "primary_image", "is_active", "created_at", "updated_at")

    def get_primary_image(self, obj):
        return obj.primary_image

class ProductAttributeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductAttribute
        fields = ["id", "key", "value"]
