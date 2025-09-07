from django.urls import path
from .views import AddToCart, ViewCart, Checkout, OrderHistory

urlpatterns = [
    path("cart/add/", AddToCart.as_view(), name="add_to_cart"),
    path("cart/view/", ViewCart.as_view(), name="view_cart"),
    path("cart/checkout/", Checkout.as_view(), name="checkout"),
    path("cart/orders/", OrderHistory.as_view(), name="order_history"),
]
