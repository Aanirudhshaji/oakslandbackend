from django.contrib import admin
from .models import Category, Product, ProductImage, ProductAttribute


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "slug", "is_active")
    list_filter = ("is_active",)
    prepopulated_fields = {"slug": ("name",)}
    search_fields = ("name", "description")
    ordering = ("name",)


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "slug",
        "price",
        "is_active",
        "stock",
        "created_at",
        "updated_at",
    )
    list_filter = ("is_active", "created_at", "updated_at")
    list_editable = ("is_active", "stock")
    prepopulated_fields = {"slug": ("name",)}
    search_fields = ("name", "sku", "description")
    filter_horizontal = ("categories",)
    ordering = ("-created_at",)


@admin.register(ProductImage)
class ProductImageAdmin(admin.ModelAdmin):
    list_display = ("id", "product", "alt_text")
    search_fields = ("product__name",)


@admin.register(ProductAttribute)
class ProductAttributeAdmin(admin.ModelAdmin):
    list_display = ("id", "product", "key", "value")
    list_filter = ("key", "value")
    search_fields = ("product__name", "key", "value")





