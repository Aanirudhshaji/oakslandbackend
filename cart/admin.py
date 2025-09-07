from django.contrib import admin
from .models import Order, CartItem


class OrderItemInline(admin.TabularInline):
    """
    Inline CartItems inside Order admin (via ManyToMany 'through' table).
    """
    model = Order.items.through
    extra = 0
    verbose_name = "Cart Item"
    verbose_name_plural = "Cart Items"
    fields = ("cartitem", "product", "quantity", "line_total")
    readonly_fields = ("product", "quantity", "line_total")

    def product(self, instance):
        return instance.cartitem.product.name

    def quantity(self, instance):
        return instance.cartitem.quantity

    def line_total(self, instance):
        return instance.cartitem.total_price()
    line_total.short_description = "Line Total"


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "status", "total_amount", "created_at")
    list_filter = ("status", "created_at")
    search_fields = ("user__username", "id")
    readonly_fields = ("total_amount", "created_at")
    inlines = [OrderItemInline]
    ordering = ("-created_at",)


@admin.register(CartItem)
class CartItemAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "product", "quantity", "total_price_display")
    list_filter = ("user", "product")
    search_fields = ("product__name", "user__username")
    readonly_fields = ("total_price_display",)

    def total_price_display(self, obj):
        return obj.total_price()
    total_price_display.short_description = "Total Price"
